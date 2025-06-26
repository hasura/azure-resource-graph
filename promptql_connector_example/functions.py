"""
functions.py

This is an example of how you can use the Python SDK's built-in Function connector to easily write Python code.
When you add a Python Lambda connector to your Hasura project, this file is generated for you!

In this file you'll find code examples that will help you get up to speed with the usage of the Hasura lambda connector.
If you are an old pro and already know what is going on you can get rid of these example functions and start writing your own code.
"""
from hasura_ndc import start
from hasura_ndc.instrumentation import with_active_span # If you aren't planning on adding additional tracing spans, you don't need this!
from opentelemetry.trace import get_tracer # If you aren't planning on adding additional tracing spans, you don't need this either!
from hasura_ndc.function_connector import FunctionConnector
from pydantic import BaseModel, Field # You only need this import if you plan to have complex inputs/outputs, which function similar to how frameworks like FastAPI do
import asyncio # You might not need this import if you aren't doing asynchronous work
from hasura_ndc.errors import UnprocessableContent
from typing import Annotated, List
from azure_resource_graph import AzureConfig, AzureResourceGraphClient

connector = FunctionConnector()

# This last section shows you how to add Otel tracing to any of your functions!
tracer = get_tracer("ndc-sdk-python.server") # You only need a tracer if you plan to add additional Otel spans

client = AzureResourceGraphClient()


class StorageEncryptionResult(BaseModel):
    application: str = Field(..., description="The name of the application (e.g., 'AnalyticsApp').")
    compliance_status: str = Field(..., description="The compliance status (e.g., 'Partially Compliant').")
    encryption_method: str = Field(..., description="The storage encryption method (e.g., 'Platform Managed + HTTPS').")
    location: str = Field(..., description="Location where the storage exists (e.g., 'centralus').")
    resource_group: str = Field(..., description="The associated resource group (e.g., 'mytalktools').")
    resource_id: str = Field(..., description="The full resource ID.")
    storage_resource: str = Field(...,
                                  description="The name of the specific storage resource (e.g., 'mytalktoolsdiag').")
    storage_type: str = Field(..., description="The type of storage (e.g., 'Storage Account').")
    additional_details: str = Field(...,
                                    description="Additional details about the resource (e.g., 'HTTPS: Optional | Public: Allowed').")

def parse_storage_encryption_results(data: List[dict]) -> List[StorageEncryptionResult]:
    """
    Parse raw data into a list of validated StorageEncryptionResult objects.

    Parameters:
        data (List[dict]): The list of raw dictionaries to validate/convert.

    Returns:
        List[StorageEncryptionResult]: A list of validated Pydantic objects.
    """

    # Helper function to convert keys from Pascal case to snake case
    def pascal_to_snake(key: str) -> str:
        import re
        return re.sub(r'(?<!^)(?=[A-Z])', '_', key).lower()

    # Transform keys to snake case and validate the input data into Pydantic models
    return [
        StorageEncryptionResult(**{pascal_to_snake(k): v for k, v in item.items()})
        for item in data
    ]

# Utilizing with_active_span allows the programmer to add Otel tracing spans
@connector.register_query
async def application_storage_encryption() -> List[StorageEncryptionResult]:
    return parse_storage_encryption_results(client.query_storage_encryption())


if __name__ == "__main__":
    start(connector)
