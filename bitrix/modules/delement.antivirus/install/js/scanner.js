(function (window, document) {
    'use strict';

    function ready(callback) {
        if (document.readyState !== 'loading') {
            callback();
            return;
        }

        document.addEventListener('DOMContentLoaded', callback);
    }

    function setText(element, value) {
        if (element) {
            element.textContent = String(value);
        }
    }

    ready(function () {
        var form = document.getElementById('delement-antivirus-scan-form');
        var startButton = document.getElementById('delement-antivirus-start');
        var cancelButton = document.getElementById('delement-antivirus-cancel');
        var output = document.getElementById('delement-antivirus-output');
        var progressBar = document.getElementById('delement-antivirus-progress-bar');
        var statusNode = document.getElementById('delement-antivirus-status');
        var processedNode = document.getElementById('delement-antivirus-processed');
        var totalNode = document.getElementById('delement-antivirus-total');
        var foundNode = document.getElementById('delement-antivirus-found');
        var errorsNode = document.getElementById('delement-antivirus-errors');
        var currentNode = document.getElementById('delement-antivirus-current');
        var activeScanId = null;
        var cancelled = false;

        if (!form || !startButton || !cancelButton || !output) {
            return;
        }

        function request(action, data, onComplete) {
            var xhr = new XMLHttpRequest();
            var formData = new FormData(form);
            var key;

            formData.append('action', action);

            if (data) {
                for (key in data) {
                    if (Object.prototype.hasOwnProperty.call(data, key)) {
                        formData.append(key, data[key]);
                    }
                }
            }

            xhr.open('POST', form.action, true);
            xhr.onreadystatechange = function () {
                var response;

                if (xhr.readyState !== 4) {
                    return;
                }

                try {
                    response = JSON.parse(xhr.responseText);
                } catch (error) {
                    onComplete({
                        success: false,
                        error: xhr.responseText || 'request_failed'
                    });
                    return;
                }

                onComplete(response);
            };

            xhr.send(formData);
        }

        function updateProgress(data) {
            var total = parseInt(data.total_files_estimated || 0, 10);
            var processed = parseInt(data.processed_files || 0, 10);
            var percent = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;

            setText(statusNode, data.status || 'unknown');
            setText(processedNode, processed);
            setText(totalNode, total);
            setText(foundNode, data.found_total || 0);
            setText(errorsNode, data.runtime_errors || 0);
            setText(currentNode, data.current_file || '');

            if (progressBar) {
                progressBar.style.width = percent + '%';
            }
        }

        function show(data) {
            output.textContent = JSON.stringify(data, null, 2);
        }

        function finish(data) {
            activeScanId = null;
            startButton.disabled = false;
            cancelButton.disabled = true;
            updateProgress(data);
            show(data);
        }

        function step() {
            if (!activeScanId || cancelled) {
                return;
            }

            request('scan_step', { scan_id: activeScanId }, function (response) {
                if (!response.success) {
                    finish(response);
                    return;
                }

                updateProgress(response);
                show(response);

                if (response.status === 'running' || response.status === 'created') {
                    window.setTimeout(step, 200);
                    return;
                }

                finish(response);
            });
        }

        startButton.addEventListener('click', function () {
            cancelled = false;
            activeScanId = null;
            startButton.disabled = true;
            cancelButton.disabled = false;
            output.textContent = 'Starting...';

            if (progressBar) {
                progressBar.style.width = '0';
            }

            request('start_scan', null, function (response) {
                if (!response.success) {
                    finish(response);
                    return;
                }

                activeScanId = response.scan_id;
                updateProgress(response);
                show(response);
                step();
            });
        });

        cancelButton.addEventListener('click', function () {
            if (!activeScanId) {
                return;
            }

            cancelled = true;

            request('cancel_scan', { scan_id: activeScanId }, function (response) {
                finish(response);
            });
        });
    });
})(window, document);
