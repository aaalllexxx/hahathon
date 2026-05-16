from app.config import settings


def get_openai_client():
    import httpx
    from openai import OpenAI

    # Force https to avoid 301 redirect that changes POST → GET
    base_url = settings.OPENAI_BASE_URL
    if base_url and base_url.startswith("http://"):
        base_url = "https://" + base_url[7:]

    http_client = httpx.Client(
        timeout=settings.OPENAI_TIMEOUT,
        follow_redirects=True,
    )
    return OpenAI(
        base_url=base_url,
        api_key=settings.OPENAI_API_KEY,
        timeout=settings.OPENAI_TIMEOUT,
        http_client=http_client,
    )
