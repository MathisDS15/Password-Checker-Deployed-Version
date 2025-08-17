async function hashPassword(event) {
    event.preventDefault();

    const password = document.getElementById('password').value;
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    try {
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashedPassword = hashArray.map(b =>
            b.toString(16).padStart(2, '0')).join('');

        document.getElementById('hashed_password').value = hashedPassword;
        event.target.submit();
    } catch (error) {
        console.error('Erreur de hachage:', error);
    }
}