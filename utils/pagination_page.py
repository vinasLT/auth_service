from fastapi import Query
from fastapi_pagination import Page
from fastapi_pagination.customization import CustomizedPage, UseParamsFields, UseFieldsAliases
from pydantic import BaseModel

def create_pagination_page(pydantic_model: type[BaseModel])-> type[Page[BaseModel]]:
    return CustomizedPage[
        Page[pydantic_model],
        UseParamsFields(size=Query(5, ge=1, le=1000)),
        UseFieldsAliases(
            items="data",
            total='count'
        )
    ]