const uploadForm = document.getElementById('upload-form');
const output = document.getElementById('output');
const artifactList = document.getElementById('artifact-list');
const uploadStatus = document.getElementById('upload-status');

async function refreshArtifacts() {
  const response = await fetch('/api/artifacts');
  const data = await response.json();
  artifactList.innerHTML = '';

  for (const artifact of data.artifacts) {
    const li = document.createElement('li');
    li.textContent = `${artifact.filename} (${Math.round(artifact.size_bytes / 1024)} KB) - ${artifact.created_at}`;
    artifactList.appendChild(li);
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

  const response = await fetch('/api/upload', { method: 'POST', body: formData });
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
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
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

refreshArtifacts();
