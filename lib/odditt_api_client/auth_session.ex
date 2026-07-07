defmodule OddittApiClient.AuthSession do
  @moduledoc """
  Convenience authentication layer over the generated client (hand-written).

  Kept in .openapi-generator-ignore so regeneration preserves it.

  The API accepts two credential types, both exchanged for a short-lived Bearer
  JWT at a login endpoint:

    * an API key           -> POST /v1/auth/login  (sends the X-API-Key header)
    * client_id + secret   -> POST /v1/oauth/login (body {client_id, client_secret})

  A session is a small process that holds the current token and refreshes it as
  needed. Call `connection/1` to get a `Tesla` connection carrying a valid Bearer
  token, then pass it to any generated API function:

      {:ok, session} = OddittApiClient.AuthSession.from_api_key("YOUR_API_KEY")
      conn = OddittApiClient.AuthSession.connection(session)
      {:ok, keys} = OddittApiClient.Api.Account.v1_account_api_keys_get(conn)

      {:ok, session} =
        OddittApiClient.AuthSession.from_client_credentials("CLIENT_ID", "CLIENT_SECRET")
  """

  alias OddittApiClient.Api.Authentication
  alias OddittApiClient.Connection
  alias OddittApiClient.Model.AuthOAuthLoginRequest
  alias OddittApiClient.Model.AuthRefreshRequest

  defstruct [:api_key, :client_id, :client_secret, :base_url, :skew_seconds]

  @doc "Start a session from an API key. Returns `{:ok, pid}`."
  @spec from_api_key(String.t(), keyword()) :: Agent.on_start()
  def from_api_key(api_key, opts \\ []) do
    start_link(Keyword.merge(opts, api_key: api_key))
  end

  @doc "Start a session from OAuth client credentials. Returns `{:ok, pid}`."
  @spec from_client_credentials(String.t(), String.t(), keyword()) :: Agent.on_start()
  def from_client_credentials(client_id, client_secret, opts \\ []) do
    start_link(Keyword.merge(opts, client_id: client_id, client_secret: client_secret))
  end

  @doc "Start a session process from a keyword list of credentials/options."
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts) do
    session = %__MODULE__{
      api_key: opts[:api_key],
      client_id: opts[:client_id],
      client_secret: opts[:client_secret],
      base_url: opts[:base_url],
      skew_seconds: opts[:skew_seconds] || 60
    }

    Agent.start_link(fn -> %{session: session, token_pair: nil, expires_at: nil} end)
  end

  @doc """
  Returns a `Tesla` connection carrying a valid Bearer token, logging in or
  refreshing as needed.
  """
  @spec connection(pid()) :: Tesla.Client.t()
  def connection(agent) do
    token = bearer_token(agent)
    %{session: session} = Agent.get(agent, & &1)

    opts = [bearer_token: token]
    opts = if session.base_url, do: Keyword.put(opts, :base_url, session.base_url), else: opts
    Connection.new(opts)
  end

  # -- internals -------------------------------------------------------------

  defp bearer_token(agent) do
    state = Agent.get(agent, & &1)

    if valid?(state) do
      state.token_pair.access_token
    else
      pair = obtain(state)
      Agent.update(agent, fn s -> %{s | token_pair: pair, expires_at: expiry(pair)} end)
      pair.access_token
    end
  end

  defp valid?(%{token_pair: nil}), do: false
  defp valid?(%{expires_at: nil}), do: false

  defp valid?(%{expires_at: expires_at, session: session}) do
    threshold = DateTime.add(expires_at, -session.skew_seconds, :second)
    DateTime.compare(DateTime.utc_now(), threshold) == :lt
  end

  defp obtain(%{token_pair: %{refresh_token: refresh_token}, session: session})
       when is_binary(refresh_token) do
    refresh(session, refresh_token)
  end

  defp obtain(%{session: session}), do: login(session)

  defp login(%{api_key: api_key} = session) when is_binary(api_key) do
    {:ok, pair} = Authentication.v1_auth_login_post(auth_conn(session), api_key)
    pair
  end

  defp login(%{client_id: client_id, client_secret: client_secret} = session) do
    body = %AuthOAuthLoginRequest{client_id: client_id, client_secret: client_secret}
    {:ok, pair} = Authentication.v1_oauth_login_post(auth_conn(session), body)
    pair
  end

  defp refresh(session, refresh_token) do
    body = %AuthRefreshRequest{refresh_token: refresh_token}

    result =
      if is_binary(session.api_key),
        do: Authentication.v1_auth_refresh_post(auth_conn(session), body),
        else: Authentication.v1_oauth_refresh_post(auth_conn(session), body)

    case result do
      {:ok, pair} -> pair
      _ -> login(session)
    end
  end

  defp auth_conn(%{base_url: nil}), do: Connection.new()
  defp auth_conn(%{base_url: base_url}), do: Connection.new(base_url: base_url)

  defp expiry(%{expires_at: %DateTime{} = expires_at}), do: expires_at

  defp expiry(%{expires_in: seconds}) when is_integer(seconds) and seconds > 0 do
    DateTime.add(DateTime.utc_now(), seconds, :second)
  end

  defp expiry(_pair), do: DateTime.add(DateTime.utc_now(), 3600, :second)
end
