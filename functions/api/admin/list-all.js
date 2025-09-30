// List all sync projects in KV (admin function)
// Requires X-KV-Admin-Key header matching env.KV_ADMIN_KEY

export async function onRequestPost(context) {
  const { env, request } = context;

  // Check if KV_ADMIN_KEY is configured
  if (!env.KV_ADMIN_KEY) {
    return new Response(JSON.stringify({
      success: false,
      error: 'KV_ADMIN_KEY not configured on server'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Note': 'kv_admin_key_missing' }
    });
  }

  // Verify KV_ADMIN_KEY from header
  const adminKey = request.headers.get('X-KV-Admin-Key');
  if (!adminKey || adminKey !== env.KV_ADMIN_KEY) {
    return new Response(JSON.stringify({
      success: false,
      error: 'Unauthorized: Invalid or missing admin key'
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const syncProjects = [];
    let cursor = undefined;

    // List all keys with prefix 'sync:'
    do {
      const res = await env.AUTH_KV.list({ prefix: 'sync:', cursor });
      for (const k of res.keys) {
        const syncId = k.name.startsWith('sync:') ? k.name.slice('sync:'.length) : k.name;

        // Get the encrypted data
        const value = await env.AUTH_KV.get(k.name);
        if (!value) continue;

        try {
          const data = JSON.parse(value);
          syncProjects.push({
            syncId,
            metadata: {
              version: data.v || 1,
              hasData: !!(data.iv && data.ct),
              updatedAt: k.metadata?.updatedAt || null,
            },
            encryptedData: data, // Include full encrypted payload
          });
        } catch (e) {
          // Skip invalid JSON
          continue;
        }
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);

    return new Response(JSON.stringify({
      success: true,
      total: syncProjects.length,
      projects: syncProjects
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store'
      }
    });
  } catch (e) {
    console.error('Error listing all projects:', e);
    return new Response(JSON.stringify({
      success: false,
      error: 'Server Error'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Note': 'error' }
    });
  }
}
