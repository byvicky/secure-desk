import os

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
def test_filters_are_visible_and_can_be_used(page: Page):
    page.goto(BASE_URL)
    for selector in ("#filter-status", "#filter-category", "#filter-priority"):
        expect(page.locator(selector)).to_be_visible()
    page.locator("#filter-status").select_option("resolvido")
