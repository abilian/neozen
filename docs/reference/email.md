# Email Reference

**Module**: `neozen.core.email`

## EmailMessage

```python
from neozen.core.email.base import EmailMessage

message = EmailMessage(
    to="alice@example.com",
    subject="Welcome!",
    body_text="Hello, Alice!",
    body_html="<p>Hello, <b>Alice</b>!</p>",
)
```

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `to` | str \| list[str] | (required) | Recipient(s) |
| `subject` | str | (required) | Subject line |
| `body_text` | str | (required) | Plain text body |
| `body_html` | str \| None | None | HTML body |
| `from_addr` | str \| None | None | Sender address |
| `reply_to` | str \| None | None | Reply-to address |
| `headers` | dict[str, str] | {} | Custom headers |

## EmailSenderProtocol

```python
class EmailSenderProtocol(Protocol):
    async def send(self, message: EmailMessage) -> None: ...
```

## ConsoleEmailSender

Prints emails to stdout. Useful for development.

```python
from neozen.core.email.console import ConsoleEmailSender

sender = ConsoleEmailSender()
await sender.send(message)

# Access sent messages (for testing)
assert len(sender.sent_messages) == 1
sender.clear_sent_messages()
```

Output:
```
============================================================
EMAIL
============================================================
To: alice@example.com
Subject: Welcome!
------------------------------------------------------------
Hello, Alice!
============================================================
```

## SMTPEmailSender

Sends via SMTP. Supports TLS/SSL and authentication.

```python
from neozen.core.email.smtp import SMTPEmailSender

sender = SMTPEmailSender(
    host="smtp.example.com",
    port=587,
    username="user",
    password="pass",
    use_tls=True,
    default_from="noreply@example.com",
)
await sender.send(message)
```

## Custom Sender

Implement `EmailSenderProtocol` for any email backend:

```python
class SESEmailSender:
    def __init__(self, ses_client):
        self._client = ses_client

    async def send(self, message: EmailMessage) -> None:
        await self._client.send_email(
            Source=message.from_addr,
            Destination={"ToAddresses": message.recipients},
            Message={
                "Subject": {"Data": message.subject},
                "Body": {"Text": {"Data": message.body_text}},
            },
        )
```
