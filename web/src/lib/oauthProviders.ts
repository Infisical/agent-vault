// Built-in OAuth provider presets for the credential form. Selecting one
// prefills the endpoint fields; users always supply their own client ID/secret.
export interface ScopePreset {
  value: string;
  description: string;
}

export interface OAuthProviderPreset {
  id: string;
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  tokenAuthMethod: "client_secret_post" | "client_secret_basic";
  suggestedKey: string;
  scopes?: ScopePreset[];
}

export const OAUTH_PROVIDERS: OAuthProviderPreset[] = [
  {
    id: "github",
    name: "GitHub",
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "GITHUB",
    scopes: [
      { value: "repo", description: "Full access to private repositories" },
      { value: "read:user", description: "Read user profile data" },
      { value: "user:email", description: "Read user email addresses" },
      { value: "read:org", description: "Read organization membership" },
      { value: "workflow", description: "Update GitHub Actions workflows" },
      { value: "gist", description: "Create and read gists" },
    ],
  },
  {
    id: "google",
    name: "Google",
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "GOOGLE",
    scopes: [
      { value: "openid", description: "OpenID Connect authentication" },
      { value: "email", description: "View user email address" },
      { value: "profile", description: "View basic profile info" },
      { value: "https://www.googleapis.com/auth/calendar", description: "Manage Google Calendar" },
      { value: "https://www.googleapis.com/auth/drive", description: "Full access to Google Drive" },
      { value: "https://www.googleapis.com/auth/gmail.readonly", description: "Read Gmail messages" },
      { value: "https://www.googleapis.com/auth/spreadsheets", description: "Read and write Google Sheets" },
    ],
  },
  {
    id: "gitlab",
    name: "GitLab",
    authorizationUrl: "https://gitlab.com/oauth/authorize",
    tokenUrl: "https://gitlab.com/oauth/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "GITLAB",
    scopes: [
      { value: "api", description: "Full API access" },
      { value: "read_api", description: "Read-only API access" },
      { value: "read_user", description: "Read user profile info" },
      { value: "read_repository", description: "Read repository files" },
      { value: "write_repository", description: "Write to repositories" },
      { value: "openid", description: "OpenID Connect authentication" },
    ],
  },
  {
    id: "discord",
    name: "Discord",
    authorizationUrl: "https://discord.com/oauth2/authorize",
    tokenUrl: "https://discord.com/api/oauth2/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "DISCORD",
    scopes: [
      { value: "identify", description: "Read user profile info" },
      { value: "email", description: "Read user email address" },
      { value: "guilds", description: "List user's guilds/servers" },
      { value: "bot", description: "Add a bot to a guild" },
      { value: "messages.read", description: "Read messages in channels" },
    ],
  },
  {
    id: "spotify",
    name: "Spotify",
    authorizationUrl: "https://accounts.spotify.com/authorize",
    tokenUrl: "https://accounts.spotify.com/api/token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "SPOTIFY",
    scopes: [
      { value: "user-read-email", description: "Read user email address" },
      { value: "user-read-private", description: "Read user subscription details" },
      { value: "playlist-read-private", description: "Read private playlists" },
      { value: "playlist-modify-public", description: "Create and edit public playlists" },
      { value: "user-library-read", description: "Read saved tracks and albums" },
      { value: "streaming", description: "Control playback on devices" },
    ],
  },
  {
    id: "slack",
    name: "Slack",
    authorizationUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "SLACK",
    scopes: [
      { value: "channels:read", description: "View basic channel info" },
      { value: "channels:history", description: "View messages in public channels" },
      { value: "chat:write", description: "Post messages to channels" },
      { value: "users:read", description: "View user profiles" },
      { value: "users:read.email", description: "View user email addresses" },
      { value: "files:read", description: "View files shared in channels" },
    ],
  },
  {
    id: "microsoft",
    name: "Microsoft",
    authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "MICROSOFT",
    scopes: [
      { value: "openid", description: "OpenID Connect authentication" },
      { value: "profile", description: "Read user basic profile" },
      { value: "email", description: "Read user email address" },
      { value: "User.Read", description: "Read signed-in user profile" },
      { value: "Mail.Read", description: "Read user mail" },
      { value: "Calendars.ReadWrite", description: "Read and write calendar events" },
      { value: "Files.ReadWrite", description: "Read and write OneDrive files" },
      { value: "offline_access", description: "Maintain access via refresh tokens" },
    ],
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
    scopes: [
      { value: "read", description: "Read access to Linear data" },
      { value: "write", description: "Write access to Linear data" },
      { value: "issues:create", description: "Create new issues" },
      { value: "admin", description: "Admin access to workspace settings" },
    ],
  },
  {
    id: "bitbucket",
    name: "Bitbucket",
    authorizationUrl: "https://bitbucket.org/site/oauth2/authorize",
    tokenUrl: "https://bitbucket.org/site/oauth2/access_token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "BITBUCKET",
    scopes: [
      { value: "repository", description: "Read repositories" },
      { value: "repository:write", description: "Write to repositories" },
      { value: "pullrequest", description: "Read pull requests" },
      { value: "pullrequest:write", description: "Create and update pull requests" },
      { value: "account", description: "Read user account info" },
    ],
  },
  {
    id: "dropbox",
    name: "Dropbox",
    authorizationUrl: "https://www.dropbox.com/oauth2/authorize",
    tokenUrl: "https://api.dropboxapi.com/oauth2/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "DROPBOX",
    scopes: [
      { value: "files.metadata.read", description: "Read file and folder metadata" },
      { value: "files.content.read", description: "Read file contents" },
      { value: "files.content.write", description: "Create and write files" },
      { value: "sharing.read", description: "Read shared files and folders" },
      { value: "account_info.read", description: "Read basic account info" },
    ],
  },
  {
    id: "twitch",
    name: "Twitch",
    authorizationUrl: "https://id.twitch.tv/oauth2/authorize",
    tokenUrl: "https://id.twitch.tv/oauth2/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "TWITCH",
    scopes: [
      { value: "user:read:email", description: "Read user email address" },
      { value: "channel:read:subscriptions", description: "List channel subscribers" },
      { value: "channel:manage:broadcast", description: "Update channel stream settings" },
      { value: "chat:read", description: "View live chat messages" },
      { value: "chat:edit", description: "Send live chat messages" },
    ],
  },
  {
    id: "zoom",
    name: "Zoom",
    authorizationUrl: "https://zoom.us/oauth/authorize",
    tokenUrl: "https://zoom.us/oauth/token",
    tokenAuthMethod: "client_secret_basic",
    suggestedKey: "ZOOM",
    scopes: [
      { value: "user:read", description: "Read user profile info" },
      { value: "meeting:read", description: "Read meeting details" },
      { value: "meeting:write", description: "Create and update meetings" },
      { value: "recording:read", description: "Read cloud recordings" },
    ],
  },
  {
    id: "hubspot",
    name: "HubSpot",
    authorizationUrl: "https://app.hubspot.com/oauth/authorize",
    tokenUrl: "https://api.hubapi.com/oauth/v1/token",
    tokenAuthMethod: "client_secret_post",
    suggestedKey: "HUBSPOT",
    scopes: [
      { value: "crm.objects.contacts.read", description: "Read contact records" },
      { value: "crm.objects.contacts.write", description: "Create and update contacts" },
      { value: "crm.objects.companies.read", description: "Read company records" },
      { value: "crm.objects.deals.read", description: "Read deal records" },
      { value: "crm.objects.deals.write", description: "Create and update deals" },
      { value: "content", description: "Manage website content and blogs" },
    ],
  },
];
