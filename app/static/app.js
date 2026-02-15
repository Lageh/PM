const uploadForm = document.getElementById('upload-form');
const output = document.getElementById('output');
const artifactList = document.getElementById('artifact-list');
const uploadStatus = document.getElementById('upload-status');

function formatSize(bytes) {
  if (!bytes) return '0 B';
  const kb = bytes / 1024;
  if (kb < 1024) return `${Math.max(1, Math.round(kb))} KB`;
  return `${(kb / 1024).toFixed(2)} MB`;
}

function artifactMarkup(artifact) {
  const notes = artifact.notes ? ` • ${artifact.notes}` : '';
  return `
    <article class="artifact-item">
      <div class="artifact-title">${artifact.filename}</div>
      <div class="artifact-meta">${formatSize(artifact.size_bytes)} • ${artifact.created_at}${notes}</div>
    </article>
  `;
}

async function refreshArtifacts() {
  try {
    const response = await fetch('/api/artifacts');
    const data = await response.json();
    artifactList.innerHTML = '';

    if (!Array.isArray(data.artifacts) || data.artifacts.length === 0) {
      artifactList.innerHTML = '<li class="artifact-item">Nenhum artefato enviado ainda.</li>';
      return;
    }

    artifactList.innerHTML = data.artifacts.map(artifactMarkup).join('');
  } catch (error) {
    artifactList.innerHTML = '<li class="artifact-item">Falha ao carregar artefatos.</li>';
  }
}

uploadForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById('file');
  const notes = document.getElementById('notes').value;

  if (!fileInput.files[0]) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('notes', notes);

  uploadStatus.textContent = 'Enviando arquivo...';

  try {
    const response = await fetch('/api/upload', { method: 'POST', body: formData });
    const data = await response.json();
    uploadStatus.textContent = data.message || data.detail || 'Upload concluído.';
    fileInput.value = '';
    document.getElementById('notes').value = '';
    await refreshArtifacts();
  } catch (error) {
    uploadStatus.textContent = 'Falha no upload. Tente novamente.';
  }
});

async function postJSON(url, payload) {
  output.textContent = 'Processando...';
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (data.answer) output.textContent = data.answer;
    if (data.insights) output.textContent = data.insights;
    if (data.report) output.textContent = data.report;
    if (data.detail) output.textContent = data.detail;
  } catch (error) {
    output.textContent = 'Falha na solicitação. Verifique o servidor.';
  }
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

refreshArtifacts();
