document.addEventListener("click", (e) => {
  if (e.target && e.target.id === "copy-json") {
    const btn = e.target;
    try {
      const payload = btn.getAttribute("data-json");
      navigator.clipboard.writeText(payload).then(() => {
        btn.textContent = "Copied!";
        setTimeout(() => (btn.textContent = "Copy JSON"), 1200);
      });
    } catch (err) {
      console.error(err);
    }
  }
});
