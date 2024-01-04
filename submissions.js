function submitForm() {
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;

    // Create an object with the user data
    const userData = {
        name: name,
        email: email
    };

    // Send the user data to the server using fetch
    fetch('/api/user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
    })
    .then(response => response.json())
    .then(result => {
        console.log('Server response:', result);
        // Handle the server response as needed
        alert('User submitted successfully!');
    })
    .catch(error => console.error('Error:', error));
}
