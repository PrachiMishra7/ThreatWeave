export const api = {
  async fetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`/api${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  },
  
  // Placeholders for future use
  alerts: {
    list: (limit = 50) => api.fetch(`/alerts?limit=${limit}`),
  },
  campaigns: {
    list: () => api.fetch(`/campaigns`),
    get: (id: string) => api.fetch(`/campaigns/${id}`),
  },
};
