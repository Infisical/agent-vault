package infisical

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"

	"math"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/infisical/go-sdk/packages/models"
	"github.com/infisical/go-sdk/packages/util"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
)

type InfisicalClient struct {
	authMethod       util.AuthMethod
	credential       interface{}
	tokenDetails     MachineIdentityCredential
	lastFetchedTime  time.Time
	firstFetchedTime time.Time

	mu sync.RWMutex

	// refreshMu is used to prevent concurrent token refreshes.
	// Only one refresh should happen at a time to avoid race conditions.
	refreshMu sync.Mutex

	cache *expirable.LRU[string, interface{}]

	httpClient       *resty.Client
	defaultTransport http.RoundTripper
	config           Config

	secrets        SecretsInterface
	folders        FoldersInterface
	auth           AuthInterface
	dynamicSecrets DynamicSecretsInterface
	kms            KmsInterface
	ssh            SshInterface

	logger zerolog.Logger
}

type InfisicalClientInterface interface {
	UpdateConfiguration(config Config)
	Secrets() SecretsInterface
	Folders() FoldersInterface
	Auth() AuthInterface
	DynamicSecrets() DynamicSecretsInterface
	Kms() KmsInterface
	Ssh() SshInterface
}

type ExponentialBackoffStrategy struct {
	// Base delay between retries. Defaults to 1 second
	BaseDelay time.Duration

	// Maximum number of retries. Defaults to 3
	MaxRetries int

	// Maximum delay between retries. Defaults to 30 seconds
	MaxDelay time.Duration
}

func (s *ExponentialBackoffStrategy) GetDelay(retryCount int) time.Duration {

	if s.BaseDelay == 0 {
		s.BaseDelay = 1 * time.Second
	}

	if s.MaxDelay == 0 {
		s.MaxDelay = 30 * time.Second
	}

	if s.MaxRetries == 0 {
		s.MaxRetries = 3
	}

	delay := s.BaseDelay * time.Duration(math.Pow(2, float64(retryCount)))

	// if delay is greater than the user-configured max delay, set the delay to the max delay
	if delay > s.MaxDelay {
		delay = s.MaxDelay
	}

	return s.Jitter(delay)
}

func (s *ExponentialBackoffStrategy) Jitter(delay time.Duration) time.Duration {
	// 20% jitter, negative and positive

	jitterFactor := 0.2

	// generates random value in [-0.2, +0.2] range
	randomFactor := (rand.Float64()*2 - 1) * jitterFactor
	jitter := time.Duration(randomFactor * float64(delay))
	return delay + jitter
}

type RetryRequestsConfig struct {
	ExponentialBackoff *ExponentialBackoffStrategy
}

type Config struct {
	SiteUrl       string `default:"https://app.infisical.com"`
	CaCertificate string
	// Transport overrides the HTTP transport for all Infisical API requests,
	// including login and token refresh. TLS settings belong to a custom
	// transport; CaCertificate is applied only when Transport is nil.
	Transport            http.RoundTripper
	LogLevel             LogLevel // Specify the log level for the SDK. If set to debug, the SDK will print to stdout with verbose logging. Defaults to no logging.
	UserAgent            string   `default:"infisical-go-sdk"` // User-Agent header to be used on requests sent by the SDK. Defaults to `infisical-go-sdk`. Do not modify this unless you have a reason to do so.
	AutoTokenRefresh     *bool    // Whether or not to automatically refresh the auth token after using one of the .Auth() methods. Defaults to `true` when nil. Pass a pointer to `false` to disable.
	SilentMode           bool     // If enabled, the SDK will not print any warnings to the console.
	CacheExpiryInSeconds int      // Defines how long certain API responses should be cached in memory, in seconds. When set to a positive value, responses from specific fetch API requests (like secret fetching) will be cached for this duration. Set to 0 to disable caching. Defaults to 0.
	CustomHeaders        map[string]string
	RetryRequestsConfig  *RetryRequestsConfig
	LogWriter            io.Writer
}

func setupLogger(logLevel LogLevel, logWriter io.Writer) zerolog.Logger {
	// very annoying but zerolog doesn't allow us to change one color without changing all of them
	// these are the default colors for each level, except for warn
	levelColors := map[string]string{
		"trace": "\033[35m", // magenta
		"debug": "\033[33m", // yellow
		"info":  "\033[32m", // green
		"warn":  "\033[33m", // yellow (this one is custom, the default is red \033[31m)
		"error": "\033[31m", // red
		"fatal": "\033[31m", // red
		"panic": "\033[31m", // red
	}

	// map full level names to abbreviated forms (default zerolog behavior)
	// see consoleDefaultFormatLevel, in zerolog for example
	levelAbbrev := map[string]string{
		"trace": "TRC",
		"debug": "DBG",
		"info":  "INF",
		"warn":  "WRN",
		"error": "ERR",
		"fatal": "FTL",
		"panic": "PNC",
	}

	// default to stderr
	if logWriter == nil {
		logWriter = os.Stderr
	}

	logger := log.Output(zerolog.ConsoleWriter{
		Out:        logWriter,
		TimeFormat: time.RFC3339,

		FormatLevel: func(i interface{}) string {
			level := fmt.Sprintf("%s", i)
			color := levelColors[level]
			if color == "" {
				color = "\033[0m" // no color for unknown levels
			}
			abbrev := levelAbbrev[level]
			if abbrev == "" {
				abbrev = strings.ToUpper(level) // fallback to uppercase if unknown
			}
			return color + abbrev + "\033[0m"
		},
	})

	if logLevel != "" {
		level, err := zerolog.ParseLevel(string(logLevel))
		if err != nil {
			logger.Warn().Msgf("Invalid log level: %s", logLevel)
		} else {
			logger = logger.Level(level)
			logger.Debug().Msgf("Infisical SDK log level set to %s", logLevel)
		}
	} else {
		logger = logger.Level(zerolog.InfoLevel)
	}

	return logger
}

// autoTokenRefreshEnabled returns true if AutoTokenRefresh is unset (nil) or
// explicitly set to true. nil is treated as the default-on case so that
// callers who omit the field keep the historical behavior, while callers that
// pass a pointer to false can actually disable the background refresh.
func autoTokenRefreshEnabled(cfg Config) bool {
	return cfg.AutoTokenRefresh == nil || *cfg.AutoTokenRefresh
}

func setDefaults(cfg *Config) {
	t := reflect.TypeOf(*cfg) // we need to dereference the pointer to get the struct type
	v := reflect.ValueOf(cfg).Elem()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		defaultVal := field.Tag.Get("default")
		if defaultVal == "" {
			continue
		}

		switch field.Type.Kind() {
		case reflect.Int:
			if v.Field(i).Int() == 0 {
				val, _ := strconv.Atoi(defaultVal)
				v.Field(i).SetInt(int64(val))
			}
		case reflect.String:
			if v.Field(i).String() == "" {
				v.Field(i).SetString(defaultVal)
			}
		}
	}
}

// BoolPtr returns a pointer to the given bool value. Use this helper when
// setting AutoTokenRefresh in Config, e.g.: AutoTokenRefresh: infisical.BoolPtr(false).
func BoolPtr(v bool) *bool { return &v }

func (c *InfisicalClient) setAccessToken(tokenDetails MachineIdentityCredential, credential interface{}, authMethod util.AuthMethod) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tokenDetails = tokenDetails
	c.lastFetchedTime = time.Now()

	if c.authMethod != authMethod || c.firstFetchedTime.IsZero() {
		c.firstFetchedTime = time.Now()
		c.authMethod = authMethod
	}

	c.credential = credential
	c.httpClient.SetAuthScheme("Bearer")
	c.httpClient.SetAuthToken(c.tokenDetails.AccessToken)
}

func (c *InfisicalClient) clearAccessToken() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tokenDetails = MachineIdentityCredential{}
	c.authMethod = ""
	c.httpClient.SetAuthScheme("")
	c.httpClient.SetAuthToken("")
}
func (c *InfisicalClient) setPlainAccessToken(accessToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authMethod = util.ACCESS_TOKEN
	c.httpClient.SetAuthScheme("Bearer")
	c.httpClient.SetAuthToken(accessToken)

	c.tokenDetails.AccessToken = accessToken
	c.credential = models.AccessTokenCredential{AccessToken: accessToken}
}

func NewInfisicalClient(context context.Context, config Config) InfisicalClientInterface {
	logger := setupLogger(config.LogLevel, config.LogWriter)

	client := &InfisicalClient{
		logger: logger,
	}
	setDefaults(&config)
	client.UpdateConfiguration(config) // set httpClient and config

	// add interfaces here
	client.secrets = NewSecrets(client)
	client.folders = NewFolders(client)
	client.auth = NewAuth(client)
	client.dynamicSecrets = NewDynamicSecrets(client)
	client.kms = NewKms(client)
	client.ssh = NewSsh(client)
	if config.CacheExpiryInSeconds != 0 {
		// hard limit set at 1000 cache items until forced eviction
		client.cache = expirable.NewLRU[string, interface{}](1000, nil, time.Second*time.Duration(config.CacheExpiryInSeconds))
	}

	if autoTokenRefreshEnabled(config) {
		go client.handleTokenLifeCycle(context)
	}

	return client
}

func (c *InfisicalClient) UpdateConfiguration(config Config) {
	c.mu.Lock()
	defer c.mu.Unlock()

	setDefaults(&config)
	config.SiteUrl = util.AppendAPIEndpoint(config.SiteUrl)
	c.config = config

	if c.httpClient == nil {
		c.httpClient = resty.New().
			SetHeader("User-Agent", config.UserAgent).
			SetBaseURL(config.SiteUrl)

		maxRetries := 3
		maxWaitTime := 30 * time.Second

		if config.RetryRequestsConfig != nil && config.RetryRequestsConfig.ExponentialBackoff != nil {
			maxRetries = config.RetryRequestsConfig.ExponentialBackoff.MaxRetries
			maxWaitTime = 10 * time.Minute
		}

		c.httpClient.SetRetryCount(maxRetries).
			SetRetryWaitTime(1 * time.Second).
			SetRetryMaxWaitTime(maxWaitTime).
			SetRetryAfter(func(rc *resty.Client, r *resty.Response) (time.Duration, error) {

				if config.RetryRequestsConfig != nil && config.RetryRequestsConfig.ExponentialBackoff != nil {
					delay := config.RetryRequestsConfig.ExponentialBackoff.GetDelay(r.Request.Attempt)
					if !config.SilentMode {
						util.PrintWarning(c.logger, fmt.Sprintf("Request failed, [url=%s] [status=%d] [method=%s]\nRetrying in %s (attempt %d)", r.Request.URL, r.StatusCode(), r.Request.Method, delay.String(), r.Request.Attempt))
					}
					return delay, nil
				}

				attempt := r.Request.Attempt + 1
				if attempt <= 0 {
					attempt = 1
				}
				waitTime := math.Min(float64(rc.RetryWaitTime)*math.Pow(2, float64(attempt-1)), float64(rc.RetryMaxWaitTime))

				// Add jitter of +/-20%
				jitterFactor := 0.8 + (rand.Float64() * 0.4)
				waitTime = waitTime * jitterFactor

				waitDuration := time.Duration(waitTime)
				return waitDuration, nil
			}).
			AddRetryCondition(func(r *resty.Response, err error) bool {
				// don't retry if there's no error or it's a timeout
				if errors.Is(err, context.DeadlineExceeded) {
					return false
				}

				if err == nil && r == nil {
					return false
				}

				if config.RetryRequestsConfig != nil && config.RetryRequestsConfig.ExponentialBackoff != nil {
					if (r != nil && r.IsError()) || err != nil {
						return r.Request.Attempt <= config.RetryRequestsConfig.ExponentialBackoff.MaxRetries
					}
				}

				networkErrors := []string{
					"connection refused",
					"connection reset",
					"network",
					"connection",
					"no such host",
					"i/o timeout",
					"dial tcp",
					"broken pipe",
					"wsaetimeout",
					"wsaeconnreset",
					"econnreset",
					"econnrefused",
					"ehostunreach",
					"enetunreach",
				}

				isConditionMet := false

				var netErr net.Error
				if errors.As(err, &netErr) {
					return true
				}

				if err != nil {
					for _, netErr := range networkErrors {
						errMsg := err.Error()

						if strings.Contains(strings.ToLower(errMsg), netErr) {
							isConditionMet = true
							break
						}
					}
				}

				return isConditionMet

			})

		// OnBeforeRequest hook to validate and refresh token before each request.
		// This is a safety net to catch cases where the background token lifecycle
		// goroutine might miss a refresh window due to timing issues (GC pauses,
		// CPU contention, etc.). Most requests will not trigger a refresh here
		// because the background goroutine handles proactive token management.
		if autoTokenRefreshEnabled(config) {
			c.httpClient.OnBeforeRequest(c.beforeRequestAuthInterceptor)
		}
	} else {
		c.httpClient.
			SetHeader("User-Agent", config.UserAgent).
			SetBaseURL(config.SiteUrl)
	}
	if c.defaultTransport == nil {
		c.defaultTransport = c.httpClient.GetClient().Transport
	}
	transport := config.Transport
	if transport == nil {
		transport = c.defaultTransport
	}
	c.httpClient.SetTransport(transport)

	if len(config.CustomHeaders) > 0 {
		c.httpClient.SetHeaders(config.CustomHeaders)
	}

	if config.CaCertificate != "" && config.Transport == nil {
		caCertPool, err := x509.SystemCertPool()
		if err != nil && !config.SilentMode {
			util.PrintWarning(c.logger, fmt.Sprintf("failed to load system root CA pool: %v", err))
		}

		if ok := caCertPool.AppendCertsFromPEM([]byte(config.CaCertificate)); !ok && !config.SilentMode {
			util.PrintWarning(c.logger, "failed to append CA certificate")
		}

		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}

		c.httpClient.SetTLSClientConfig(tlsConfig)
	}
}

func (c *InfisicalClient) Secrets() SecretsInterface {
	return c.secrets
}

func (c *InfisicalClient) Folders() FoldersInterface {
	return c.folders
}

func (c *InfisicalClient) Auth() AuthInterface {
	return c.auth
}

func (c *InfisicalClient) DynamicSecrets() DynamicSecretsInterface {
	return c.dynamicSecrets
}

func (c *InfisicalClient) Kms() KmsInterface {
	return c.kms
}

func (c *InfisicalClient) Ssh() SshInterface {
	return c.ssh
}

func (c *InfisicalClient) handleTokenLifeCycle(context context.Context) {
	var warningPrinted = false

	for {
		select {
		case <-context.Done():
			return // The context has been cancelled, clean up and return from the loop to stop the goroutine
		default:
			c.mu.RLock()
			config := c.config
			authMethod := c.authMethod
			tokenDetails := c.tokenDetails
			c.mu.RUnlock()

			if autoTokenRefreshEnabled(config) && authMethod != "" && authMethod != util.ACCESS_TOKEN {
				// Print warning once for short TTLs
				if !config.SilentMode && !warningPrinted && tokenDetails.AccessTokenMaxTTL != 0 && tokenDetails.ExpiresIn != 0 {
					if tokenDetails.AccessTokenMaxTTL < 60 || tokenDetails.ExpiresIn < 60 {
						util.PrintWarning(c.logger, "Machine Identity access token TTL or max TTL is less than 60 seconds. This may cause excessive API calls, and you may be subject to rate-limits.")
					}
					warningPrinted = true
				}

				// Check if token needs refresh (using the same buffer as OnBeforeRequest)
				if c.isTokenExpiringSoon(renewalBufferSeconds) {
					// Use refreshTokenSynchronously which handles both renewal and re-auth
					// Pass false for manualTrigger since this is from the background goroutine
					if err := c.refreshTokenSynchronously(false); err != nil {
						c.logger.Debug().Msgf("Background token refresh failed: %s", err.Error())
					}

					// Re-read token details after refresh attempt
					c.mu.RLock()
					tokenDetails = c.tokenDetails
					c.mu.RUnlock()
				}

				// Calculate sleep time until next check
				sleepTime := c.calculateSleepTime(tokenDetails, renewalBufferSeconds)

				if err := util.SleepWithContext(context, sleepTime); err != nil && (err == util.ErrContextCanceled || errors.Is(err, util.ErrContextDeadlineExceeded)) {
					return
				}
			} else {
				if err := util.SleepWithContext(context, 1*time.Second); err != nil && (err == util.ErrContextCanceled || errors.Is(err, util.ErrContextDeadlineExceeded)) {
					return
				}
			}
		}
	}
}
