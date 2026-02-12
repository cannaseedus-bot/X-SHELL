export function downloadArtifact(cpeJson) {
  const blob = new Blob([JSON.stringify(cpeJson, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "artifact.json";
  anchor.click();

  URL.revokeObjectURL(url);
}
