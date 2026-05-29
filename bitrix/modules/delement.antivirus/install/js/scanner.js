(function (window, document) {
    'use strict';

    function ready(callback) {
        if (document.readyState !== 'loading') {
            callback();
            return;
        }

        document.addEventListener('DOMContentLoaded', callback);
    }

    ready(function () {
        var button = document.getElementById('delement-antivirus-ping');
        var form = document.getElementById('delement-antivirus-scan-form');
        var output = document.getElementById('delement-antivirus-output');

        if (!button || !form || !output) {
            return;
        }

        button.addEventListener('click', function () {
            var request = new XMLHttpRequest();
            var formData = new FormData(form);

            button.disabled = true;
            output.textContent = '...';

            request.open('POST', form.action, true);
            request.onreadystatechange = function () {
                if (request.readyState !== 4) {
                    return;
                }

                button.disabled = false;

                try {
                    output.textContent = JSON.stringify(JSON.parse(request.responseText), null, 2);
                } catch (error) {
                    output.textContent = request.responseText || 'Request failed';
                }
            };

            request.send(formData);
        });
    });
})(window, document);
