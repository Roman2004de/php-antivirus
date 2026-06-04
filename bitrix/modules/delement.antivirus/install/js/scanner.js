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

    function getMessages() {
        return window.DelementAntivirusScannerMessages || {};
    }

    function getMessage(key) {
        var messages = getMessages();

        return messages[key] || '';
    }

    function statusLabel(status) {
        var labels = getMessages().statuses || {};
        var key = String(status || '').toLowerCase();

        return labels[key] || status || labels.unknown || 'unknown';
    }

    function localizeStatusesForDisplay(value, key) {
        var result;
        var itemKey;

        if (Array.isArray(value)) {
            return value.map(function (item) {
                return localizeStatusesForDisplay(item);
            });
        }

        if (value && typeof value === 'object') {
            result = {};

            for (itemKey in value) {
                if (Object.prototype.hasOwnProperty.call(value, itemKey)) {
                    result[itemKey] = localizeStatusesForDisplay(value[itemKey], itemKey);
                }
            }

            return result;
        }

        if (key === 'status' && typeof value === 'string') {
            return statusLabel(value);
        }

        return value;
    }

    function setButtonDisabled(button, disabled) {
        if (!button) {
            return;
        }

        button.disabled = disabled;
        button.setAttribute('aria-disabled', disabled ? 'true' : 'false');

        if (button.classList) {
            if (disabled) {
                button.classList.add('delement-antivirus-disabled');
            } else {
                button.classList.remove('delement-antivirus-disabled');
            }
        }
    }

    function isDiscoveryDone(data) {
        var status = String(data.status || '').toLowerCase();

        if (data.discovery_done === true || data.discovery_done === 'true' || data.discovery_done === '1') {
            return true;
        }

        return status === 'finished' || status === 'failed' || status === 'cancelled' || status === 'canceled';
    }

    ready(function () {
        var form = document.getElementById('delement-antivirus-scan-form');
        var startButton = document.getElementById('delement-antivirus-start');
        var cancelButton = document.getElementById('delement-antivirus-cancel');
        var output = document.getElementById('delement-antivirus-output');
        var progressNode = document.getElementById('delement-antivirus-progress');
        var progressBar = document.getElementById('delement-antivirus-progress-bar');
        var progressValue = document.getElementById('delement-antivirus-progress-value');
        var progressNative = document.getElementById('delement-antivirus-progress-native');
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

        setButtonDisabled(cancelButton, true);
        setText(statusNode, statusLabel('idle'));

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
                        error: xhr.responseText || getMessage('request_failed') || 'request_failed'
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
            var discoveryDone = isDiscoveryDone(data);
            var percent = discoveryDone && total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;
            var status = data.status || (data.success === false ? 'failed' : 'unknown');
            var progressText = discoveryDone ? percent + '%' : (getMessage('discovering') || '');

            setText(statusNode, statusLabel(status));
            setText(processedNode, processed);
            setText(totalNode, discoveryDone ? total : '...');
            setText(foundNode, data.found_total || 0);
            setText(errorsNode, data.runtime_errors || 0);
            setText(currentNode, data.current_file || '');

            if (progressBar) {
                progressBar.style.width = percent + '%';
            }

            if (progressNode) {
                progressNode.setAttribute('aria-valuenow', String(percent));
                if (progressNode.classList) {
                    if (discoveryDone) {
                        progressNode.classList.remove('delement-antivirus-progress-discovering');
                    } else {
                        progressNode.classList.add('delement-antivirus-progress-discovering');
                    }
                }
            }

            setText(progressValue, progressText);

            if (progressNative) {
                if (discoveryDone) {
                    progressNative.value = percent;
                } else {
                    progressNative.removeAttribute('value');
                }

                progressNative.textContent = progressText;
            }
        }

        function show(data) {
            output.textContent = JSON.stringify(localizeStatusesForDisplay(data), null, 2);
        }

        function finish(data) {
            activeScanId = null;
            setButtonDisabled(startButton, false);
            setButtonDisabled(cancelButton, true);
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
            setButtonDisabled(startButton, true);
            setButtonDisabled(cancelButton, true);
            setText(statusNode, statusLabel('running'));
            output.textContent = getMessage('starting') || statusLabel('running');

            if (progressBar) {
                progressBar.style.width = '0';
            }

            if (progressNode) {
                progressNode.setAttribute('aria-valuenow', '0');
                if (progressNode.classList) {
                    progressNode.classList.remove('delement-antivirus-progress-discovering');
                }
            }

            setText(progressValue, '0%');

            if (progressNative) {
                progressNative.value = 0;
                progressNative.textContent = '0%';
            }

            request('start_scan', null, function (response) {
                if (!response.success) {
                    if (response.error === 'scan_already_running' && response.active_scan_id) {
                        activeScanId = response.active_scan_id;
                        updateProgress(response);
                        show(response);
                        setButtonDisabled(startButton, true);
                        setButtonDisabled(cancelButton, false);
                        window.setTimeout(step, 200);
                        return;
                    }

                    finish(response);
                    return;
                }

                activeScanId = response.scan_id;
                setButtonDisabled(cancelButton, false);
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
