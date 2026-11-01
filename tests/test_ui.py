import os
from uuid import uuid4

from playwright.sync_api import Page, expect
import pytest


BASE_URL = os.getenv("SECUREDESK_BASE_URL", "http://127.0.0.1:8000")
WEB_PASSWORD = os.getenv("SECUREDESK_WEB_PASSWORD", "test-password")


def login(page: Page):
    page.goto(BASE_URL)
    page.locator('#login-form [name="password"]').fill(WEB_PASSWORD)
    page.locator("#login-form button").click()
    expect(page.locator("#ticket-form")).to_be_visible(timeout=10_000)


@pytest.mark.ui
def test_ticket_submission_appears_in_list(page: Page):
    login(page)
    page.locator('[name="requester"]').fill("Teste Playwright")
    page.locator('[name="title"]').fill("Notebook sem conexão")
    page.locator('[name="description"]').fill(
        "O notebook de teste não conecta à rede Wi-Fi."
    )
    page.locator("#ticket-form button.primary").click()

    expect(page.locator("#form-message")).to_contain_text(
        "registrada", timeout=10_000
    )
    expect(page.locator("#ticket-list")).to_contain_text(
        "Notebook sem conexão", timeout=10_000
    )


@pytest.mark.ui
def test_filters_change_the_visible_tickets(page: Page):
    login(page)
    suffix = uuid4().hex[:8]
    open_title = f"Chamado aberto {suffix}"
    resolved_title = f"Chamado resolvido {suffix}"

    for title, status in ((open_title, "aberto"), (resolved_title, "resolvido")):
        response = page.request.post(
            f"{BASE_URL}/api/tickets",
            data={
                "requester": "Teste Playwright",
                "title": title,
                "description": "Solicitação criada para validar os filtros da interface.",
            },
        )
        assert response.status == 201, response.text()
        if status == "resolvido":
            ticket_id = response.json()["id"]
            update = page.request.patch(
                f"{BASE_URL}/api/tickets/{ticket_id}",
                data={"status": "resolvido"},
            )
            assert update.status == 200, update.text()

    page.reload()
    expect(page.locator("#ticket-list")).to_contain_text(open_title)
    expect(page.locator("#ticket-list")).to_contain_text(resolved_title)

    page.locator("#filter-status").select_option("resolvido")
    expect(page.locator("#ticket-list")).to_contain_text(resolved_title)
    expect(page.locator("#ticket-list")).not_to_contain_text(open_title)


@pytest.mark.ui
def test_invalid_login_does_not_open_dashboard(page: Page):
    page.goto(BASE_URL)
    page.locator('#login-form [name="password"]').fill("wrong-password")
    page.locator("#login-form button").click()
    expect(page.locator("#login-message")).to_contain_text("Senha incorreta.")
    expect(page.locator("#ticket-form")).to_be_hidden()
