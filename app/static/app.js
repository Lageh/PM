const output = document.getElementById('output');
const artifactList = document.getElementById('artifact-list');
const uploadStatus = document.getElementById('upload-status');
const authStatus = document.getElementById('auth-status');
const ragOutput = document.getElementById('rag-output');
const kpiOutput = document.getElementById('kpi-output');
const auditOutput = document.getElementById('audit-output');

const apiKeyInput = document.getElementById('api-key');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

const LOCAL_KEY_NAME = 'pm-insights-openai-key';
const LOCAL_AUTH_TOKEN = 'pm-insights-auth-token';

function getApiKey() {
  return (apiKeyInput?.value || '').trim();
}

function getAuthToken() {
  return localStorage.getItem(LOCAL_AUTH_TOKEN) || '';
}

function authHeaders(json = true) {
  const headers = {};
  if (json) headers['Content-Type'] = 'application/json';
  const token = getAuthToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

if (apiKeyInput) {
  apiKeyInput.value = localStorage.getItem(LOCAL_KEY_NAME) || '';
  apiKeyInput.addEventListener('input', () => localStorage.setItem(LOCAL_KEY_NAME, apiKeyInput.value || ''));
}

async function login() {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: usernameInput.value, password: passwordInput.value }),
  });
  const data = await response.json();
  if (data.token) {
    localStorage.setItem(LOCAL_AUTH_TOKEN, data.token);
    authStatus.textContent = `Autenticado como ${data.user.username}`;
    await refreshArtifacts();
  } else {
    authStatus.textContent = data.detail || 'Falha no login';
  }
}

async function refreshArtifacts() {
  const response = await fetch('/api/artifacts', { headers: authHeaders(false) });
  const data = await response.json();
  artifactList.innerHTML = '';
  if (!data.artifacts) {
    artifactList.innerHTML = '<li>Faça login para listar artefatos.</li>';
    return;
  }

  for (const artifact of data.artifacts) {
    const li = document.createElement('li');
    const hasText = artifact.extracted_text && artifact.extracted_text.length > 0;
    li.textContent = `#${artifact.id} ${artifact.filename} (${Math.round(artifact.size_bytes / 1024)} KB) ${hasText ? '• texto indexado' : ''}`;
    artifactList.appendChild(li);
  }
}

document.getElementById('login-btn').addEventListener('click', login);

document.getElementById('upload-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById('file');
  const notes = document.getElementById('notes').value;
  if (!fileInput.files[0]) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('notes', notes);

  const response = await fetch('/api/upload', {
    method: 'POST',
    headers: authHeaders(false),
    body: formData,
  });
  const data = await response.json();
  uploadStatus.textContent = data.message || data.detail;
  fileInput.value = '';
  document.getElementById('notes').value = '';
  await refreshArtifacts();
});

async function postJSON(url, payload) {
  output.textContent = 'Processando...';
  const response = await fetch(url, {
    method: 'POST',
    headers: authHeaders(true),
    body: JSON.stringify({ ...payload, api_key: getApiKey() }),
  });
  const data = await response.json();
  if (data.answer) output.textContent = data.answer;
  if (data.insights) output.textContent = data.insights;
  if (data.report) output.textContent = data.report;
  if (data.detail) output.textContent = data.detail;
}

document.getElementById('ask-btn').addEventListener('click', async () => {
  const question = document.getElementById('question').value;
  await postJSON('/api/ask', { question });
});

document.getElementById('insights-btn').addEventListener('click', async () => {
  await postJSON('/api/insights', { objective: 'Mapear riscos, gargalos e oportunidades de aceleração.' });
});

document.getElementById('report-btn').addEventListener('click', async () => {
  await postJSON('/api/report', { report_type: 'Status executivo semanal' });
});

document.getElementById('transcribe-btn').addEventListener('click', async () => {
  const artifactId = Number(document.getElementById('transcribe-artifact-id').value || 0);
  const response = await fetch('/api/transcribe', {
    method: 'POST',
    headers: authHeaders(true),
    body: JSON.stringify({ artifact_id: artifactId, api_key: getApiKey() }),
  });
  const data = await response.json();
  output.textContent = JSON.stringify(data, null, 2);
  await refreshArtifacts();
});

document.getElementById('rag-btn').addEventListener('click', async () => {
  const query = document.getElementById('rag-query').value;
  const response = await fetch('/api/rag/search', {
    method: 'POST',
    headers: authHeaders(true),
    body: JSON.stringify({ query }),
  });
  const data = await response.json();
  ragOutput.textContent = JSON.stringify(data, null, 2);
});

document.getElementById('dashboard-btn').addEventListener('click', async () => {
  const response = await fetch('/api/dashboard', { headers: authHeaders(false) });
  const data = await response.json();
  kpiOutput.textContent = JSON.stringify(data, null, 2);
});

document.getElementById('audit-btn').addEventListener('click', async () => {
  const response = await fetch('/api/audit?limit=50', { headers: authHeaders(false) });
  const data = await response.json();
  auditOutput.textContent = JSON.stringify(data, null, 2);
});

if (getAuthToken()) {
  authStatus.textContent = 'Token encontrado no navegador.';
  refreshArtifacts();
}
