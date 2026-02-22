document.addEventListener("DOMContentLoaded", function() {
    const consoleDiv = document.getElementById('log-console');
    if (!consoleDiv) return;

    // Connect to the FastAPI SSE endpoint
    const eventSource = new EventSource('/admin/stream/logs');

    eventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            const record = data.record;

            const logLine = document.createElement('div');

            // Basic color coding based on Loguru levels
            if (record.level.name === 'ERROR') {
                logLine.className = 'log-error';
            } else if (record.level.name === 'INFO') {
                logLine.className = 'log-info';
            }

            logLine.textContent = `[${record.time.repr}] ${record.level.name}: ${record.message}`;
            consoleDiv.appendChild(logLine);

            // Auto-scroll to bottom
            consoleDiv.scrollTop = consoleDiv.scrollHeight;

        } catch (e) {
            console.error("Failed to parse log event", e);
        }
    };

    eventSource.onerror = function(err) {
        console.error("EventSource failed. Browser will attempt to reconnect.", err);
    };
});
