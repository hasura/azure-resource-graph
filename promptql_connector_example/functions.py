"""
functions.py

Complete Azure Resource Graph analysis functions for Hasura Lambda connector.
Includes all available queries from the Azure Resource Graph Client.
All functions return List[PydanticModel] as required by register_query.
"""
from hasura_ndc import start
from hasura_ndc.instrumentation import with_active_span
from opentelemetry.trace import get_tracer
from hasura_ndc.function_connector import FunctionConnector
from hasura_ndc.errors import UnprocessableContent
from typing import Annotated, List, Optional, Dict, Any
from pydantic import BaseModel, Field
import asyncio

# Import the Azure client and all its models
from azure_resource_graph import AzureConfig, AzureResourceGraphClient
from azure_resource_graph.models import (
    # Storage models
    StorageResource, StorageAccessControlResult, StorageBackupResult,
    StorageOptimizationResult, StorageComplianceSummary,

    # VM Governance models
    VMSecurityResult, VMOptimizationResult, VMExtensionResult,
    VMPatchComplianceResult, VMGovernanceSummary,

    # Network models
    NSGRule, NetworkResource, CertificateAnalysisResult,
    NetworkTopologyResult, ResourceOptimizationResult, NetworkComplianceSummary,

    # IAM models
    RoleAssignmentResult, KeyVaultSecurityResult, ManagedIdentityResult,
    CustomRoleResult, IAMComplianceSummary,

    # Container Workloads models
    AKSClusterSecurityResult, AKSNodePoolResult, ContainerRegistrySecurityResult,
    AppServiceSecurityResult, AppServiceSlotResult, ContainerWorkloadsComplianceSummary,

    # Legacy models
    ComplianceSummary
)

connector = FunctionConnector()
tracer = get_tracer("ndc-sdk-python.server")

# Initialize Azure client
client = AzureResourceGraphClient()

# ============================================================================
# ADDITIONAL PYDANTIC MODELS FOR COMPREHENSIVE ANALYSIS
# ============================================================================

class ApplicationStorageResource(BaseModel):
    """Pydantic model for application-specific storage resources"""
    application: str = Field(..., description="Application name")
    storage_resource: str = Field(..., description="Storage resource name")
    storage_type: str = Field(..., description="Type of storage resource")
    resource_group: str = Field(..., description="Resource group name")
    location: str = Field(..., description="Azure region location")
    tags: Dict[str, Any] = Field(default_factory=dict, description="Resource tags")
    resource_id: str = Field(..., description="Full Azure resource ID")

class ComprehensiveAnalysisResult(BaseModel):
    """Pydantic model for comprehensive analysis results"""
    category: str = Field(..., description="Analysis category (storage, vm_governance, network, iam, container_workloads)")
    subcategory: str = Field(..., description="Analysis subcategory")
    resource_count: int = Field(..., description="Number of resources analyzed")
    high_risk_count: int = Field(..., description="Number of high-risk resources")
    medium_risk_count: int = Field(..., description="Number of medium-risk resources")
    low_risk_count: int = Field(..., description="Number of low-risk resources")
    compliance_score: float = Field(..., description="Overall compliance score for this category")
    summary: str = Field(..., description="Summary of findings")

class ApplicationAnalysisResult(BaseModel):
    """Pydantic model for application-specific analysis results"""
    application: str = Field(..., description="Application name")
    category: str = Field(..., description="Analysis category")
    subcategory: str = Field(..., description="Analysis subcategory")
    resource_count: int = Field(..., description="Number of resources for this application")
    issues_count: int = Field(..., description="Number of issues found")
    compliance_score: float = Field(..., description="Compliance score for this application category")
    risk_level: str = Field(..., description="Overall risk level (High/Medium/Low)")
    summary: str = Field(..., description="Summary of findings for this application")

class ContainerWorkloadsAnalysisResult(BaseModel):
    """Pydantic model for comprehensive container workloads analysis"""
    analysis_type: str = Field(..., description="Type of container workloads analysis")
    resource_count: int = Field(..., description="Number of resources analyzed")
    issues_count: int = Field(..., description="Number of issues found")
    compliance_score: float = Field(..., description="Compliance score")
    risk_level: str = Field(..., description="Overall risk level")
    summary: str = Field(..., description="Summary of findings")

# ============================================================================
# STORAGE ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def storage_analysis(subscription_ids: Optional[List[str]] = None) -> List[StorageResource]:
    """
    Comprehensive storage security analysis including encryption, compliance, and security findings.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage resources with security analysis
    """
    return client.query_storage_analysis(subscription_ids)

@connector.register_query
async def storage_encryption(subscription_ids: Optional[List[str]] = None) -> List[StorageResource]:
    """
    Storage encryption analysis across all storage types.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage resources with encryption status
    """
    return client.query_storage_encryption(subscription_ids)

@connector.register_query
async def storage_access_control(subscription_ids: Optional[List[str]] = None) -> List[StorageAccessControlResult]:
    """
    Storage access control and network security analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage access control analysis results
    """
    return client.query_storage_access_control(subscription_ids)

@connector.register_query
async def storage_backup_analysis(subscription_ids: Optional[List[str]] = None) -> List[StorageBackupResult]:
    """
    Storage backup configuration and disaster recovery analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage backup analysis results
    """
    return client.query_storage_backup_analysis(subscription_ids)

@connector.register_query
async def storage_optimization(subscription_ids: Optional[List[str]] = None) -> List[StorageOptimizationResult]:
    """
    Storage cost optimization and utilization analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage optimization recommendations
    """
    return client.query_storage_optimization(subscription_ids)

@connector.register_query
async def storage_compliance_summary(subscription_ids: Optional[List[str]] = None) -> List[StorageComplianceSummary]:
    """
    Storage compliance summary by application.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage compliance summaries per application
    """
    return client.get_storage_compliance_summary(subscription_ids)

# ============================================================================
# VM GOVERNANCE FUNCTIONS
# ============================================================================

@connector.register_query
async def vm_security(subscription_ids: Optional[List[str]] = None) -> List[VMSecurityResult]:
    """
    Virtual machine security analysis including encryption, extensions, and compliance.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of VM security analysis results
    """
    return client.query_vm_security(subscription_ids)

@connector.register_query
async def vm_optimization(subscription_ids: Optional[List[str]] = None) -> List[VMOptimizationResult]:
    """
    Virtual machine cost optimization and sizing analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of VM optimization recommendations
    """
    return client.query_vm_optimization(subscription_ids)

@connector.register_query
async def vm_extensions(subscription_ids: Optional[List[str]] = None) -> List[VMExtensionResult]:
    """
    Virtual machine extensions analysis for security and compliance impact.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of VM extension analysis results
    """
    return client.query_vm_extensions(subscription_ids)

@connector.register_query
async def vm_patch_compliance(subscription_ids: Optional[List[str]] = None) -> List[VMPatchComplianceResult]:
    """
    Virtual machine patch management and update compliance analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of VM patch compliance results
    """
    return client.query_vm_patch_compliance(subscription_ids)

@connector.register_query
async def vm_governance_summary(subscription_ids: Optional[List[str]] = None) -> List[VMGovernanceSummary]:
    """
    VM governance summary by application including security and optimization metrics.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of VM governance summaries per application
    """
    return client.get_vm_governance_summary(subscription_ids)

# ============================================================================
# NETWORK ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def network_analysis(subscription_ids: Optional[List[str]] = None) -> List[NetworkResource]:
    """
    Comprehensive network security analysis including NSGs, public IPs, and gateways.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of network resources with security analysis
    """
    return client.query_network_analysis(subscription_ids)

@connector.register_query
async def network_security(subscription_ids: Optional[List[str]] = None) -> List[NetworkResource]:
    """
    Network security analysis (alias for network_analysis).

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of network security analysis results
    """
    return client.query_network_security(subscription_ids)

@connector.register_query
async def nsg_detailed(subscription_ids: Optional[List[str]] = None) -> List[NSGRule]:
    """
    Detailed Network Security Group rules analysis with risk assessment.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of NSG rules with detailed security analysis
    """
    return client.query_nsg_detailed(subscription_ids)

@connector.register_query
async def certificate_analysis(subscription_ids: Optional[List[str]] = None) -> List[CertificateAnalysisResult]:
    """
    SSL/TLS certificate analysis for Application Gateways and other services.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of certificate analysis results
    """
    return client.query_certificate_analysis(subscription_ids)

@connector.register_query
async def network_topology(subscription_ids: Optional[List[str]] = None) -> List[NetworkTopologyResult]:
    """
    Network topology and configuration analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of network topology analysis results
    """
    return client.query_network_topology(subscription_ids)

@connector.register_query
async def resource_optimization(subscription_ids: Optional[List[str]] = None) -> List[ResourceOptimizationResult]:
    """
    Network resource optimization and cost analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of resource optimization recommendations
    """
    return client.query_resource_optimization(subscription_ids)

@connector.register_query
async def network_compliance_summary(subscription_ids: Optional[List[str]] = None) -> List[NetworkComplianceSummary]:
    """
    Network compliance summary by application.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of network compliance summaries per application
    """
    return client.get_network_compliance_summary(subscription_ids)

# ============================================================================
# IAM ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def role_assignments(subscription_ids: Optional[List[str]] = None) -> List[RoleAssignmentResult]:
    """
    Azure Role-Based Access Control (RBAC) assignments analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of role assignment analysis results
    """
    return client.query_role_assignments(subscription_ids)

@connector.register_query
async def key_vault_security(subscription_ids: Optional[List[str]] = None) -> List[KeyVaultSecurityResult]:
    """
    Key Vault security configuration and access control analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of Key Vault security analysis results
    """
    return client.query_key_vault_security(subscription_ids)

@connector.register_query
async def managed_identities(subscription_ids: Optional[List[str]] = None) -> List[ManagedIdentityResult]:
    """
    Managed identities analysis including usage patterns and security risks.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of managed identity analysis results
    """
    return client.query_managed_identities(subscription_ids)

@connector.register_query
async def custom_roles(subscription_ids: Optional[List[str]] = None) -> List[CustomRoleResult]:
    """
    Custom Azure roles analysis and security assessment.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of custom role analysis results
    """
    return client.query_custom_roles(subscription_ids)

@connector.register_query
async def iam_compliance_summary(subscription_ids: Optional[List[str]] = None) -> List[IAMComplianceSummary]:
    """
    Identity and Access Management compliance summary by application.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of IAM compliance summaries per application
    """
    return client.get_iam_compliance_summary(subscription_ids)

# ============================================================================
# CONTAINER WORKLOADS ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def aks_cluster_security(subscription_ids: Optional[List[str]] = None) -> List[AKSClusterSecurityResult]:
    """
    Azure Kubernetes Service (AKS) cluster security analysis including RBAC and network policies.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of AKS cluster security analysis results
    """
    return client.query_aks_cluster_security(subscription_ids)

@connector.register_query
async def aks_node_pools(subscription_ids: Optional[List[str]] = None) -> List[AKSNodePoolResult]:
    """
    AKS node pool analysis including VM sizes, scaling, and optimization.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of AKS node pool analysis results
    """
    return client.query_aks_node_pools(subscription_ids)

@connector.register_query
async def container_registry_security(subscription_ids: Optional[List[str]] = None) -> List[ContainerRegistrySecurityResult]:
    """
    Azure Container Registry security analysis including access controls and scanning policies.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of Container Registry security analysis results
    """
    return client.query_container_registry_security(subscription_ids)

@connector.register_query
async def app_service_security(subscription_ids: Optional[List[str]] = None) -> List[AppServiceSecurityResult]:
    """
    Azure App Service security analysis including TLS, authentication, and network security.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of App Service security analysis results
    """
    return client.query_app_service_security(subscription_ids)

@connector.register_query
async def app_service_deployment_slots(subscription_ids: Optional[List[str]] = None) -> List[AppServiceSlotResult]:
    """
    App Service deployment slots configuration and security analysis.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of App Service deployment slot analysis results
    """
    return client.query_app_service_deployment_slots(subscription_ids)

@connector.register_query
async def container_workloads_compliance_summary(subscription_ids: Optional[List[str]] = None) -> List[ContainerWorkloadsComplianceSummary]:
    """
    Container and modern workloads compliance summary by application.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of container workloads compliance summaries per application
    """
    return client.get_container_workloads_compliance_summary(subscription_ids)

@connector.register_query
async def comprehensive_container_workloads_analysis(subscription_ids: Optional[List[str]] = None) -> List[ContainerWorkloadsAnalysisResult]:
    """
    Comprehensive container and modern workloads analysis including all aspects.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of container workloads analysis results
    """
    with tracer.start_as_current_span("comprehensive_container_analysis"):
        try:
            # Get the raw results from client
            raw_results = client.query_comprehensive_container_workloads_analysis(subscription_ids)

            # Convert to list of Pydantic objects
            analysis_results = []

            # Process AKS clusters
            aks_clusters = raw_results.get('aks_cluster_security', [])
            if aks_clusters:
                high_risk = len([r for r in aks_clusters if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="AKS Cluster Security",
                    resource_count=len(aks_clusters),
                    issues_count=high_risk,
                    compliance_score=((len(aks_clusters) - high_risk) / len(aks_clusters) * 100) if aks_clusters else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(aks_clusters)} AKS clusters, {high_risk} with high-risk configurations"
                ))

            # Process Container Registries
            registries = raw_results.get('container_registry_security', [])
            if registries:
                high_risk = len([r for r in registries if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="Container Registry Security",
                    resource_count=len(registries),
                    issues_count=high_risk,
                    compliance_score=((len(registries) - high_risk) / len(registries) * 100) if registries else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(registries)} container registries, {high_risk} with security issues"
                ))

            # Process App Services
            app_services = raw_results.get('app_service_security', [])
            if app_services:
                high_risk = len([r for r in app_services if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="App Service Security",
                    resource_count=len(app_services),
                    issues_count=high_risk,
                    compliance_score=((len(app_services) - high_risk) / len(app_services) * 100) if app_services else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(app_services)} App Services, {high_risk} with security issues"
                ))

            # Process Node Pools
            node_pools = raw_results.get('aks_node_pools', [])
            if node_pools:
                high_risk = len([r for r in node_pools if hasattr(r, 'node_pool_risk') and 'High' in r.node_pool_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="AKS Node Pool Analysis",
                    resource_count=len(node_pools),
                    issues_count=high_risk,
                    compliance_score=((len(node_pools) - high_risk) / len(node_pools) * 100) if node_pools else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(node_pools)} node pools, {high_risk} with optimization issues"
                ))

            return analysis_results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive container workloads analysis: {str(e)}")

# ============================================================================
# LEGACY/BACKWARD COMPATIBILITY FUNCTIONS
# ============================================================================

@connector.register_query
async def compliance_summary(subscription_ids: Optional[List[str]] = None) -> List[ComplianceSummary]:
    """
    Legacy compliance summary format for backward compatibility.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of legacy compliance summaries
    """
    return client.get_compliance_summary(subscription_ids)

@connector.register_query
async def application_storage(application_name: str, subscription_ids: Optional[List[str]] = None) -> List[ApplicationStorageResource]:
    """
    Query storage resources for a specific application.

    Args:
        application_name: Name of the application to query
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of storage resources for the specified application
    """
    try:
        raw_results = client.query_application_storage(application_name, subscription_ids)

        # Convert raw dict results to Pydantic objects
        storage_resources = []
        for item in raw_results:
            storage_resource = ApplicationStorageResource(
                application=item.get('Application', application_name),
                storage_resource=item.get('StorageResource', ''),
                storage_type=item.get('StorageType', ''),
                resource_group=item.get('ResourceGroup', ''),
                location=item.get('Location', ''),
                tags=item.get('Tags', {}),
                resource_id=item.get('ResourceId', '')
            )
            storage_resources.append(storage_resource)

        return storage_resources

    except Exception as e:
        raise UnprocessableContent(f"Failed to get application storage for {application_name}: {str(e)}")

# ============================================================================
# COMPREHENSIVE ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def comprehensive_security_analysis(subscription_ids: Optional[List[str]] = None) -> List[ComprehensiveAnalysisResult]:
    """
    Comprehensive security analysis across all Azure resource types.

    Args:
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of comprehensive analysis results organized by category
    """
    with tracer.start_as_current_span("comprehensive_analysis"):
        results = []

        try:
            # Storage Analysis
            with tracer.start_as_current_span("storage_analysis_section"):
                storage_resources = client.query_storage_analysis(subscription_ids)
                storage_summaries = client.get_storage_compliance_summary(subscription_ids)

                high_risk = len([r for r in storage_resources if 'High' in r.compliance_risk])
                medium_risk = len([r for r in storage_resources if 'Medium' in r.compliance_risk])
                low_risk = len(storage_resources) - high_risk - medium_risk
                avg_compliance = sum([s.compliance_score for s in storage_summaries]) / len(storage_summaries) if storage_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="storage",
                    subcategory="security_analysis",
                    resource_count=len(storage_resources),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_compliance,
                    summary=f"Analyzed {len(storage_resources)} storage resources across {len(storage_summaries)} applications"
                ))

            # VM Governance
            with tracer.start_as_current_span("vm_governance_section"):
                vm_security = client.query_vm_security(subscription_ids)
                vm_summaries = client.get_vm_governance_summary(subscription_ids)

                high_risk = len([r for r in vm_security if 'High' in r.security_risk])
                medium_risk = len([r for r in vm_security if 'Medium' in r.security_risk])
                low_risk = len(vm_security) - high_risk - medium_risk
                avg_governance = sum([s.governance_score for s in vm_summaries]) / len(vm_summaries) if vm_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="vm_governance",
                    subcategory="security_analysis",
                    resource_count=len(vm_security),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_governance,
                    summary=f"Analyzed {len(vm_security)} VMs across {len(vm_summaries)} applications"
                ))

            # Network Analysis
            with tracer.start_as_current_span("network_analysis_section"):
                network_resources = client.query_network_security(subscription_ids)
                network_summaries = client.get_network_compliance_summary(subscription_ids)

                high_risk = len([r for r in network_resources if 'High' in r.compliance_risk])
                medium_risk = len([r for r in network_resources if 'Medium' in r.compliance_risk])
                low_risk = len(network_resources) - high_risk - medium_risk
                avg_security = sum([s.security_score for s in network_summaries]) / len(network_summaries) if network_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="network",
                    subcategory="security_analysis",
                    resource_count=len(network_resources),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_security,
                    summary=f"Analyzed {len(network_resources)} network resources across {len(network_summaries)} applications"
                ))

            # IAM Analysis
            with tracer.start_as_current_span("iam_analysis_section"):
                key_vaults = client.query_key_vault_security(subscription_ids)
                iam_summaries = client.get_iam_compliance_summary(subscription_ids)

                high_risk = len([r for r in key_vaults if 'High' in r.security_risk])
                medium_risk = len([r for r in key_vaults if 'Medium' in r.security_risk])
                low_risk = len(key_vaults) - high_risk - medium_risk
                avg_iam = sum([s.iam_compliance_score for s in iam_summaries]) / len(iam_summaries) if iam_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="iam",
                    subcategory="security_analysis",
                    resource_count=len(key_vaults),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_iam,
                    summary=f"Analyzed {len(key_vaults)} Key Vaults across {len(iam_summaries)} applications"
                ))

            # Container Workloads
            with tracer.start_as_current_span("container_workloads_section"):
                aks_clusters = client.query_aks_cluster_security(subscription_ids)
                container_summaries = client.get_container_workloads_compliance_summary(subscription_ids)

                high_risk = len([r for r in aks_clusters if hasattr(r, 'is_high_risk') and r.is_high_risk])
                medium_risk = len([r for r in aks_clusters if hasattr(r, 'security_risk') and 'Medium' in r.security_risk])
                low_risk = len(aks_clusters) - high_risk - medium_risk
                avg_container = sum([s.container_workloads_compliance_score for s in container_summaries]) / len(container_summaries) if container_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="container_workloads",
                    subcategory="security_analysis",
                    resource_count=len(aks_clusters),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_container,
                    summary=f"Analyzed {len(aks_clusters)} container workloads across {len(container_summaries)} applications"
                ))

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive analysis: {str(e)}")

@connector.register_query
async def application_analysis(application_name: str, subscription_ids: Optional[List[str]] = None) -> List[ApplicationAnalysisResult]:
    """
    Comprehensive analysis for a specific application across all resource types.

    Args:
        application_name: Name of the application to analyze
        subscription_ids: Optional list of Azure subscription IDs to query

    Returns:
        List of analysis results for the specified application
    """
    with tracer.start_as_current_span("application_specific_analysis"):
        try:
            results = []

            # Storage Analysis for Application
            storage_resources = [r for r in client.query_storage_analysis(subscription_ids) if r.application == application_name]
            if storage_resources:
                issues = len([r for r in storage_resources if 'High' in r.compliance_risk or 'Medium' in r.compliance_risk])
                compliance_score = ((len(storage_resources) - issues) / len(storage_resources) * 100) if storage_resources else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="storage",
                    subcategory="security_analysis",
                    resource_count=len(storage_resources),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(storage_resources) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(storage_resources)} storage resources with {issues} security issues"
                ))

            # VM Analysis for Application
            vm_resources = [r for r in client.query_vm_security(subscription_ids) if r.application == application_name]
            if vm_resources:
                issues = len([r for r in vm_resources if 'High' in r.security_risk or 'Medium' in r.security_risk])
                compliance_score = ((len(vm_resources) - issues) / len(vm_resources) * 100) if vm_resources else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="vm_governance",
                    subcategory="security_analysis",
                    resource_count=len(vm_resources),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(vm_resources) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(vm_resources)} VMs with {issues} security issues"
                ))

            # Network Analysis for Application
            network_resources = [r for r in client.query_network_security(subscription_ids) if r.application == application_name]
            if network_resources:
                issues = len([r for r in network_resources if 'High' in r.compliance_risk or 'Medium' in r.compliance_risk])
                compliance_score = ((len(network_resources) - issues) / len(network_resources) * 100) if network_resources else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="network",
                    subcategory="security_analysis",
                    resource_count=len(network_resources),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(network_resources) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(network_resources)} network resources with {issues} security issues"
                ))

            # IAM Analysis for Application
            key_vaults = [r for r in client.query_key_vault_security(subscription_ids) if r.application == application_name]
            if key_vaults:
                issues = len([r for r in key_vaults if 'High' in r.security_risk or 'Medium' in r.security_risk])
                compliance_score = ((len(key_vaults) - issues) / len(key_vaults) * 100) if key_vaults else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="iam",
                    subcategory="key_vault_security",
                    resource_count=len(key_vaults),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(key_vaults) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(key_vaults)} Key Vaults with {issues} security issues"
                ))

            # Container Workloads Analysis for Application
            aks_clusters = [r for r in client.query_aks_cluster_security(subscription_ids) if r.application == application_name]
            if aks_clusters:
                issues = len([r for r in aks_clusters if hasattr(r, 'is_high_risk') and r.is_high_risk])
                compliance_score = ((len(aks_clusters) - issues) / len(aks_clusters) * 100) if aks_clusters else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="container_workloads",
                    subcategory="aks_security",
                    resource_count=len(aks_clusters),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(aks_clusters) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(aks_clusters)} AKS clusters with {issues} security issues"
                ))

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform application analysis for {application_name}: {str(e)}")

if __name__ == "__main__":
    start(connector)
