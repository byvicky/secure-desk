from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal["acesso", "hardware", "software", "rede", "seguranca", "outro"]
Priority = Literal["baixa", "media", "alta", "critica"]
Status = Literal["aberto", "em_andamento", "resolvido"]


class TicketCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    requester: str = Field(min_length=2, max_length=80)
    title: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10, max_length=3000)
    category: Category | None = None

    @field_validator("requester", "title", "description")
    @classmethod
    def safe_text(cls, value: str) -> str:
        if any(ord(char) < 32 and char not in "\\n\\t" for char in value):
            raise ValueError("Caracteres de controle não permitidos.")
        return value


class TicketUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status


class TicketOut(BaseModel):
    id: int
    requester: str
    title: str
    description: str
    category: Category
    priority: Priority
    status: Status
    created_at: str
