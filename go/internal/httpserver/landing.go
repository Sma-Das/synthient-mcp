package httpserver

import (
	"net/http"
)

func landingPage(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "public, max-age=3600")
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = response.Write([]byte(landingPageHTML))
}

func robots(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "public, max-age=3600")
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = response.Write([]byte("User-agent: *\nAllow: /\nDisallow: /mcp\nDisallow: /healthz\n"))
}

const landingPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Synthient MCP Server for IP &amp; Domain Intelligence</title>
  <meta name="description" content="Run a secure, Dockerized Go MCP server for Synthient IP enrichment, batch lookup, domain honeypot intelligence, and account quota tools.">
  <meta name="robots" content="index, follow">
  <meta name="theme-color" content="#f6f8fb" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#10151f" media="(prefers-color-scheme: dark)">
  <meta property="og:type" content="website">
  <meta property="og:title" content="Synthient MCP Server for IP &amp; Domain Intelligence">
  <meta property="og:description" content="A secure, Dockerized Go MCP server for Synthient intelligence tools.">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="Synthient MCP Server for IP &amp; Domain Intelligence">
  <meta name="twitter:description" content="Connect AI clients to Synthient IP and domain intelligence through MCP.">
  <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      "name": "Synthient MCP Server",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "Docker",
      "programmingLanguage": "Go",
      "description": "A remote Model Context Protocol server for Synthient IP and domain intelligence.",
      "isAccessibleForFree": true,
      "codeRepository": "https://github.com/Sma-Das/synthient-mcp"
    }
  </script>
  <style>
    :root {
      color-scheme: light dark;
      --page: oklch(0.982 0.006 255);
      --surface: oklch(1 0 0);
      --text: oklch(0.225 0.025 255);
      --muted: oklch(0.43 0.025 255);
      --accent: oklch(0.48 0.17 255);
      --accent-text: oklch(0.99 0 0);
      --soft: oklch(0.94 0.024 255);
      --line: oklch(0.88 0.018 255);
      --focus: oklch(0.58 0.2 255);
    }

    * { box-sizing: border-box; }

    html {
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    body {
      margin: 0;
      background: var(--page);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 1rem;
      line-height: 1.6;
    }

    main {
      inline-size: min(100% - 2rem, 70rem);
      margin-inline: auto;
      padding-block: clamp(3rem, 8vw, 7rem);
    }

    .hero {
      max-inline-size: 48rem;
    }

    .eyebrow {
      display: inline-flex;
      padding: 0.3rem 0.7rem;
      border-radius: 999px;
      background: var(--soft);
      color: var(--accent);
      font-size: 0.8125rem;
      font-weight: 650;
      letter-spacing: 0.04em;
    }

    h1, h2, h3 {
      line-height: 1.12;
      text-wrap: balance;
    }

    h1 {
      margin-block: 1.25rem 1rem;
      font-size: clamp(2.5rem, 7vw, 5rem);
      letter-spacing: -0.045em;
    }

    h2 {
      margin: 0;
      font-size: clamp(1.75rem, 4vw, 2.5rem);
      letter-spacing: -0.025em;
    }

    h3 {
      margin-block: 0 0.5rem;
      font-size: 1.0625rem;
    }

    p { margin-block: 0; }

    .lede {
      max-inline-size: 65ch;
      color: var(--muted);
      font-size: clamp(1.0625rem, 2.5vw, 1.25rem);
      text-wrap: pretty;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-block-start: 2rem;
    }

    .button {
      display: inline-flex;
      min-block-size: 2.75rem;
      align-items: center;
      justify-content: center;
      padding-inline: 1rem;
      border: 1px solid var(--line);
      border-radius: 0.75rem;
      background: var(--surface);
      color: var(--text);
      font-weight: 650;
      text-decoration: none;
    }

    .button.primary {
      border-color: var(--accent);
      background: var(--accent);
      color: var(--accent-text);
    }

    a:focus-visible {
      outline: 0.1875rem solid var(--focus);
      outline-offset: 0.1875rem;
    }

    .quickstart {
      margin-block-start: 2.5rem;
      padding: 1.25rem;
      border-radius: 1rem;
      background: var(--text);
      color: var(--page);
      box-shadow: 0 1rem 3rem oklch(0.2 0.03 255 / 0.12);
      overflow-x: auto;
    }

    code {
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      font-size: 0.9375rem;
    }

    section {
      margin-block-start: clamp(5rem, 10vw, 8rem);
    }

    .section-copy {
      max-inline-size: 62ch;
      margin-block-start: 0.75rem;
      color: var(--muted);
      text-wrap: pretty;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 15rem), 1fr));
      gap: 1rem;
      margin-block-start: 2rem;
    }

    .card {
      padding: 1.25rem;
      border: 1px solid var(--line);
      border-radius: 1rem;
      background: var(--surface);
    }

    .card p {
      color: var(--muted);
      font-size: 0.9375rem;
      text-wrap: pretty;
    }

    footer {
      margin-block-start: clamp(5rem, 10vw, 8rem);
      color: var(--muted);
      font-size: 0.875rem;
    }

    footer a {
      color: var(--accent);
      text-underline-position: from-font;
      text-decoration-thickness: from-font;
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --page: oklch(0.17 0.022 255);
        --surface: oklch(0.215 0.025 255);
        --text: oklch(0.96 0.009 255);
        --muted: oklch(0.76 0.02 255);
        --accent: oklch(0.78 0.12 255);
        --accent-text: oklch(0.18 0.03 255);
        --soft: oklch(0.26 0.045 255);
        --line: oklch(0.34 0.025 255);
        --focus: oklch(0.84 0.14 255);
      }

      .quickstart {
        background: oklch(0.12 0.02 255);
        color: var(--text);
        box-shadow: none;
      }
    }

    @media (forced-colors: active) {
      .button, .card { border: 1px solid CanvasText; }
    }
  </style>
</head>
<body>
  <main>
    <header class="hero">
      <span class="eyebrow">Open source · Dockerized · Go</span>
      <h1>Synthient intelligence, ready for MCP</h1>
      <p class="lede">Connect AI clients to Synthient IP enrichment, batch lookup, and domain honeypot intelligence through a secure remote Model Context Protocol server.</p>
      <div class="actions">
        <a class="button primary" href="https://github.com/Sma-Das/synthient-mcp">View the source on GitHub</a>
        <a class="button" href="https://docs.synthient.com/">Read the Synthient API docs</a>
      </div>
      <pre class="quickstart" aria-label="Docker Compose command"><code>docker compose up --build</code></pre>
    </header>

    <section aria-labelledby="tools-heading">
      <h2 id="tools-heading">Four read-only intelligence tools</h2>
      <p class="section-copy">Use one Synthient API key from your MCP client. The server forwards it for each request and never stores or logs it.</p>
      <div class="grid">
        <article class="card">
          <h3>Account and quota</h3>
          <p>Inspect scopes, credits, and quota reset timing without exposing echoed credentials.</p>
        </article>
        <article class="card">
          <h3>IP intelligence</h3>
          <p>Enrich one IPv4 or IPv6 address with network, location, risk, and provider data.</p>
        </article>
        <article class="card">
          <h3>Batch IP lookup</h3>
          <p>Enrich as many as 1,000 IP addresses in one discounted Synthient request.</p>
        </article>
        <article class="card">
          <h3>Domain intelligence</h3>
          <p>Retrieve Helios honeypot observations, event statistics, subdomains, and ports.</p>
        </article>
      </div>
    </section>

    <section aria-labelledby="deployment-heading">
      <h2 id="deployment-heading">Built for secure remote deployment</h2>
      <p class="section-copy">The stateless Go service supports horizontal scaling, trusted-proxy configuration, host and origin validation, graceful shutdown, request limits, and container health checks.</p>
    </section>

    <footer>
      <p>Synthient MCP is an open-source integration. Visit the <a href="https://github.com/Sma-Das/synthient-mcp#readme">installation and configuration guide</a>.</p>
    </footer>
  </main>
</body>
</html>
`
