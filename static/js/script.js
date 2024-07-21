document.getElementById('prediction-form').addEventListener('submit', function(e) {
    e.preventDefault();
    let features = {
        feature1: document.getElementsByName('feature1')[0].value,
        feature2: document.getElementsByName('feature2')[0].value
        // Add more features as necessary
    };
    fetch('/predict', {
        method: 'POST',
        body: JSON.stringify({ features: features }),
        headers: { 'Content-Type': 'application/json' }
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('result').innerText = 'Prediction: ' + data.prediction;
    });
});