###1. composer install

###2. potrzebujesz kluczy VAPID

web-push generate-vapid-keys

###3. konfiguracja

src/config.php_default -> src/config.php

swój adres mailowy, oraz klucz publiczny i prywatny z #1

subskrypcję wklejasz jako jsona po prostu

i treść wiadomości

###4. leci

php run.php
