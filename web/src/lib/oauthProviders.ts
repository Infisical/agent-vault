// Built-in OAuth provider presets for the credential form. Selecting one
// prefills the endpoint fields; users always supply their own client ID/secret.
export interface OAuthProviderPreset {
  id: string;
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  tokenAuthMethod: "client_secret_post" | "client_secret_basic";
  suggestedKey: string;
}

export const OAUTH_PROVIDERS: OAuthProviderPreset[] = [
  {
    id: "github",
    name: "GitHub",
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "GITHUB",
  },
  {
    id: "google",
    name: "Google",
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "GOOGLE",
  },
  {
    id: "gitlab",
    name: "GitLab",
    authorizationUrl: "https://gitlab.com/oauth/authorize",
    tokenUrl: "https://gitlab.com/oauth/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "GITLAB",
  },
  {
    id: "discord",
    name: "Discord",
    authorizationUrl: "https://discord.com/oauth2/authorize",
    tokenUrl: "https://discord.com/api/oauth2/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "DISCORD",
  },
  {
    id: "spotify",
    name: "Spotify",
    authorizationUrl: "https://accounts.spotify.com/authorize",
    tokenUrl: "https://accounts.spotify.com/api/token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "SPOTIFY",
  },
  {
    id: "slack",
    name: "Slack",
    authorizationUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "SLACK",
  },
  {
    id: "microsoft",
    name: "Microsoft",
    authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "MICROSOFT",
  },
  {
    id: "notion",
    name: "Notion",
    authorizationUrl: "https://api.notion.com/v1/oauth/authorize",
    tokenUrl: "https://api.notion.com/v1/oauth/token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "NOTION",
  },
  {
    id: "linear",
    name: "Linear",
    authorizationUrl: "https://linear.app/oauth/authorize",
    tokenUrl: "https://api.linear.app/oauth/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "LINEAR",
  },
  {
    id: "bitbucket",
    name: "Bitbucket",
    authorizationUrl: "https://bitbucket.org/site/oauth2/authorize",
    tokenUrl: "https://bitbucket.org/site/oauth2/access_token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "BITBUCKET",
  },
  {
    id: "dropbox",
    name: "Dropbox",
    authorizationUrl: "https://www.dropbox.com/oauth2/authorize",
    tokenUrl: "https://api.dropboxapi.com/oauth2/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "DROPBOX",
  },
  {
    id: "twitch",
    name: "Twitch",
    authorizationUrl: "https://id.twitch.tv/oauth2/authorize",
    tokenUrl: "https://id.twitch.tv/oauth2/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "TWITCH",
  },
  {
    id: "zoom",
    name: "Zoom",
    authorizationUrl: "https://zoom.us/oauth/authorize",
    tokenUrl: "https://zoom.us/oauth/token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "ZOOM",
  },
  {
    id: "hubspot",
    name: "HubSpot",
    authorizationUrl: "https://app.hubspot.com/oauth/authorize",
    tokenUrl: "https://api.hubapi.com/oauth/v1/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "HUBSPOT",
  },
];
