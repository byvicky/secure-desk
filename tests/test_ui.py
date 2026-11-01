import os
from uuid import uuid4

import pytest
from playwright.sync_api import Page, expect


BASE_URL = os.getenv("SECUREDESK_BASE_URL", "http://127.0.0.1:8000")


@pytest.mark.ui
def test_ticket_submission_appears_in_list(page: Page):
    page.goto(BASE_URL)
    expect(page.locator("#ticket-form")).to_be_visible()

    page.locator('[name="requester"]').fill("Teste Playwright")
    page.locator('[name="title"]').fill("Notebook sem conexão")
    page.locator('[name="description"]').fill(
        "O notebook de teste não conecta à rede Wi-Fi."
    )
    page.locator('#ticket-form button[type="submit"]').click()

    expect(page.locator("#form-message")).to_contain_text(
        "registrada", timeout=10_000
    )
    expect(page.locator("#ticket-list")).to_contain_text(
        "Notebook sem conexão", timeout=10_000
    )


@pytest.mark.ui
def test_filters_change_the_visible_tickets(page: Page):
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

    page.goto(BASE_URL)
    expect(page.locator("#ticket-list")).to_contain_text(open_title)
    expect(page.locator("#ticket-list")).to_contain_text(resolved_title)

    page.locator("#filter-status").select_option("resolvido")
    expect(page.locator("#ticket-list")).to_contain_text(resolved_title)
    expect(page.locator("#ticket-list")).not_to_contain_text(open_title)
