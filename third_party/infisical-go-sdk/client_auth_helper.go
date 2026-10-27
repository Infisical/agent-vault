package infisical

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	api "github.com/infisical/go-sdk/packages/api/auth"
	"github.com/infisical/go-sdk/packages/models"
	"github.com/infisical/go-sdk/packages/util"
)

const renewalBufferSeconds = 5

// isTokenExpiringSoon checks if the token will expire within the given buffer time.
func (c *InfisicalClient) isTokenExpiringSoon(bufferSeconds int64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Skip if no auth method or using plain access token (no refresh capability)
	if c.authMethod == "" || c.authMethod == util.ACCESS_TOKEN {
		return false
	}

	// Skip if token details are not set
	if c.tokenDetails.ExpiresIn == 0 {
		return false
	}

	timeSinceLastFetch := time.Since(c.lastFetchedTime).Seconds()
	return timeSinceLastFetch >= float64(c.tokenDetails.ExpiresIn-bufferSeconds)
}

// refreshTokenSynchronously performs a blocking token refresh. This gets called by the onbeforerequest hook and the token lifecycle goroutine.
func (c *InfisicalClient) refreshTokenSynchronously(manualTrigger bool) error {
	c.logger.Debug().Msgf("Refreshing token synchronously. Manual trigger: %v", manualTrigger)

	// Use TryLock to prevent deadlocks when the refresh operation itself triggers HTTP requests (renewal or re-auth)
	// If we can't acquire the lock, another goroutine is already refreshing.
	if !c.refreshMu.TryLock() {
		c.logger.Debug().Msg("Another refresh is already in progress, skipping")
		return nil
	}
	defer c.refreshMu.Unlock()

	// Double-check if refresh is still needed after acquiring the lock
	// (another goroutine might have already refreshed)
	if !c.isTokenExpiringSoon(renewalBufferSeconds) {
		return nil
	}

	c.mu.RLock()
	authMethod := c.authMethod
	credential := c.credential
	tokenDetails := c.tokenDetails
	firstFetchedTime := c.firstFetchedTime
	config := c.config
	c.mu.RUnlock()

	// Check if we need re-auth (approaching max TTL) or can renew
	timeSinceFirstFetch := time.Since(firstFetchedTime).Seconds()
	timeUntilMaxTTL := float64(tokenDetails.AccessTokenMaxTTL) - timeSinceFirstFetch

	// If time until max TTL is less than the token TTL, we need to re-auth
	needsReAuth := timeUntilMaxTTL < float64(tokenDetails.ExpiresIn)

	c.logger.Debug().Msgf("timeSinceFirstFetch: %f, timeUntilMaxTTL: %f, needsReAuth: %v", timeSinceFirstFetch, timeUntilMaxTTL, needsReAuth)

	if needsReAuth {
		c.logger.Debug().Msgf("Re-authentication needed. Attempting re-authentication")
		err := c.doReAuthentication(authMethod, credential, config)

		message := "Re-authentication successful"
		if err != nil {
			message = fmt.Sprintf("Re-authentication failed. Error: %v", err)
		}

		c.logger.Debug().Msg(message)
		return err
	}

	// Try renewal first
	c.logger.Debug().Msgf("Attempting token renewal")
	err := c.doTokenRenewal(tokenDetails.AccessToken, credential, authMethod)
	if err != nil {
		c.logger.Debug().Msgf("Token renewal failed. Attempting re-authentication as fallback. Error: %v", err)
		// Renewal failed, try re-authentication as fallback
		if !config.SilentMode {
			util.PrintWarning(c.logger, fmt.Sprintf("Token renewal failed during pre-request check: %s. Attempting re-authentication", err.Error()))
		}
		message := "Re-authentication successful as fallback"
		err = c.doReAuthentication(authMethod, credential, config)

		if err != nil {
			message = fmt.Sprintf("Re-authentication failed as fallback. Error: %v", err)
		}

		c.logger.Debug().Msg(message)
		return err

	}

	c.logger.Debug().Msgf("Token renewal successful")
	return nil
}

// doTokenRenewal attempts to renew the access token.
func (c *InfisicalClient) doTokenRenewal(accessToken string, credential interface{}, authMethod util.AuthMethod) error {
	renewedCredential, err := api.CallRenewAccessToken(c.httpClient, api.RenewAccessTokenRequest{AccessToken: accessToken})
	if err != nil {
		return err
	}
	c.setAccessToken(renewedCredential, credential, authMethod)
	return nil
}

// doReAuthentication performs a full re-authentication using the stored credentials.
func (c *InfisicalClient) doReAuthentication(authMethod util.AuthMethod, credential interface{}, config Config) error {
	authStrategies := c.getAuthStrategies()

	strategy, exists := authStrategies[authMethod]
	if !exists {
		return fmt.Errorf("unknown auth method: %s", authMethod)
	}

	newToken, err := strategy(credential)
	if err != nil {
		if !config.SilentMode {
			util.PrintWarning(c.logger, fmt.Sprintf("Re-authentication failed during pre-request check: %s", err.Error()))
		}
		return err
	}

	c.setAccessToken(newToken, credential, authMethod)
	c.mu.Lock()
	c.firstFetchedTime = time.Now()
	c.mu.Unlock()

	return nil
}

// calculateSleepTime determines how long to sleep before the next token refresh check
func (c *InfisicalClient) calculateSleepTime(tokenDetails MachineIdentityCredential, bufferSeconds int64) time.Duration {
	if tokenDetails.ExpiresIn == 0 {
		return 1 * time.Second
	}

	c.mu.RLock()
	timeSinceLastFetch := time.Since(c.lastFetchedTime).Seconds()
	c.mu.RUnlock()

	timeUntilExpiry := float64(tokenDetails.ExpiresIn) - timeSinceLastFetch - float64(bufferSeconds)

	if timeUntilExpiry <= 0 {
		return 1 * time.Second
	}

	return time.Duration(timeUntilExpiry) * time.Second
}

// getAuthStrategies returns the map of authentication strategies
func (c *InfisicalClient) getAuthStrategies() map[util.AuthMethod]func(cred interface{}) (credential MachineIdentityCredential, err error) {
	return map[util.AuthMethod]func(cred interface{}) (credential MachineIdentityCredential, err error){
		util.UNIVERSAL_AUTH: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.UniversalAuthCredential); ok {
				return c.auth.UniversalAuthLogin(parsedCreds.ClientID, parsedCreds.ClientSecret)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse UniversalAuthCredential")
		},
		util.KUBERNETES: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.KubernetesCredential); ok {
				return c.auth.KubernetesRawServiceAccountTokenLogin(parsedCreds.IdentityID, parsedCreds.ServiceAccountToken)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse KubernetesAuthCredential")
		},
		util.AZURE: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.AzureCredential); ok {
				if parsedCreds.ClientID != "" {
					return c.auth.WithAzureClientID(parsedCreds.ClientID).AzureAuthLogin(parsedCreds.IdentityID, parsedCreds.Resource)
				}
				return c.auth.AzureAuthLogin(parsedCreds.IdentityID, parsedCreds.Resource)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse AzureAuthCredential")
		},
		util.GCP_ID_TOKEN: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.GCPIDTokenCredential); ok {
				return c.auth.GcpIdTokenAuthLogin(parsedCreds.IdentityID)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse GCPIDTokenCredential")
		},
		util.GCP_IAM: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.GCPIAMCredential); ok {
				return c.auth.GcpIamAuthLogin(parsedCreds.IdentityID, parsedCreds.ServiceAccountKeyFilePath)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse GCPIAMCredential")
		},
		util.AWS_IAM: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.AWSIAMCredential); ok {
				return c.auth.AwsIamAuthLogin(parsedCreds.IdentityID)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse AWSIAMCredential")
		},
		util.JWT_AUTH: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.JWTCredential); ok {
				return c.auth.JwtAuthLogin(parsedCreds.IdentityID, parsedCreds.JWT)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse JWTCredential")
		},
		util.LDAP_AUTH: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.LDAPCredential); ok {
				return c.auth.LdapAuthLogin(parsedCreds.IdentityID, parsedCreds.Username, parsedCreds.Password)
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse LDAPCredential")
		},
		util.OCI_AUTH: func(cred interface{}) (credential MachineIdentityCredential, err error) {
			if parsedCreds, ok := cred.(models.OCICredential); ok {
				return c.auth.OciAuthLogin(OciAuthLoginOptions{
					IdentityID:  parsedCreds.IdentityID,
					PrivateKey:  parsedCreds.PrivateKey,
					Fingerprint: parsedCreds.Fingerprint,
					UserID:      parsedCreds.UserID,
					TenancyID:   parsedCreds.TenancyID,
					Region:      parsedCreds.Region,
					Passphrase:  parsedCreds.Passphrase,
				})
			}
			return MachineIdentityCredential{}, fmt.Errorf("failed to parse OCICredential")
		},
	}
}

func (c *InfisicalClient) beforeRequestAuthInterceptor(client *resty.Client, req *resty.Request) error {
	// skip auth endpoints to prevent infinite loops.
	// note(daniel): req.URL contains just the path ("/v1/auth/..."), not the full URL with base.
	// the base URL has /api appended, but that's not part of req.URL at this point.
	if strings.Contains(req.URL, "/v1/auth/") && req.Method == http.MethodPost {
		return nil
	}

	// Check if token is expired or will expire within 5 seconds
	if c.isTokenExpiringSoon(renewalBufferSeconds) {
		if err := c.refreshTokenSynchronously(true); err != nil {
			// Don't fail the request on refresh error, we let the request fail with 401 as it normally would.
			// logging is already done within refreshTokenSynchronously
			return nil
		}

		c.mu.RLock()
		newToken := c.tokenDetails.AccessToken
		c.mu.RUnlock()

		if newToken != "" {
			req.SetAuthToken(newToken)
		}
	}
	return nil
}
