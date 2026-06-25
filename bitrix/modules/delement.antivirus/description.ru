<p>Добавлен отдельный механизм анализа файлов .htaccess.</p>
<ul>
  <li>Обнаружение PHP-обработчиков для статических расширений, например .jpg, .png, .gif, .txt.</li>
  <li>Обнаружение директив auto_prepend_file и auto_append_file.</li>
  <li>Обнаружение PHP/JS-маркеров внутри .htaccess, включая &lt;?php, &lt;script, eval( и base64_decode(.</li>
  <li>Обнаружение подозрительных RewriteRule и RewriteCond, включая редиректы на wp-login.php, cache.php, shell/tmp-файлы и index.php с параметрами.</li>
  <li>Обнаружение WordPress-маркеров внутри Bitrix-проекта: wp-config.php, wp-login.php, wp-admin, wp-content, wp-includes.</li>
  <li>Обнаружение директив обхода доступа в чувствительных каталогах: /upload, /bitrix/modules, /bitrix/php_interface.</li>
  <li>Добавлены отдельные сигнатуры htaccess_* и smoke-тесты для проверки .htaccess-анализатора.</li>
</ul>