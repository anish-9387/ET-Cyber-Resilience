const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

class ApiClient {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });
    if (!response.ok) throw new Error(`API error: ${response.statusText}`);
    return response.json();
  }

  // Auth
  login = (username: string, password: string) =>
    this.request<{ access_token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });

  // Agents
  getAgents = () => this.request<any[]>('/agents');
  getAgentStatus = (id: string) => this.request<any>(`/agents/${id}`);
  dispatchAgent = (agentType: string, data: any) =>
    this.request<any>(`/agents/${agentType}/dispatch`, {
      method: 'POST',
      body: JSON.stringify(data),
    });

  // Digital Twin
  getTwinGraph = () => this.request<any>('/digital-twin/graph');
  getAssetDetail = (id: string) => this.request<any>(`/digital-twin/assets/${id}`);
  runSimulation = (scenario: any) =>
    this.request<any>('/digital-twin/simulate', {
      method: 'POST',
      body: JSON.stringify(scenario),
    });
  getTwinState = () => this.request<any>('/digital-twin/state');

  // Incidents
  getIncidents = (params?: Record<string, string>) =>
    this.request<any[]>(`/incidents?${new URLSearchParams(params)}`);
  getIncidentDetail = (id: string) => this.request<any>(`/incidents/${id}`);

  // Threat Intel
  getThreatIntel = () => this.request<any>('/threat-intel/indicators');
  getMitreMatrix = () => this.request<any>('/threat-intel/mitre');

  // Analytics
  getDashboard = () => this.request<any>('/analytics/dashboard');
  getTrends = (days: number = 7) =>
    this.request<any>(`/analytics/trends?days=${days}`);
}

export const api = new ApiClient();
