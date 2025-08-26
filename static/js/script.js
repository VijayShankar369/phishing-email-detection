// JavaScript for Phishing Email Detection System
document.addEventListener('DOMContentLoaded', function() {
    const emailForm = document.getElementById('emailAnalysisForm');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    const analyzeBtn = document.getElementById('analyzeBtn');

    // Handle form submission
    if (emailForm) {
        emailForm.addEventListener('submit', function(e) {
            e.preventDefault();
            analyzeEmail();
        });
    }

    function analyzeEmail() {
        const emailText = document.getElementById('emailText').value.trim();
        
        if (!emailText) {
            showAlert('Please enter email content to analyze.', 'warning');
            return;
        }

        // Show loading state
        showLoading();
        
        // Prepare form data
        const formData = new FormData();
        formData.append('email_text', emailText);

        // Send request
        fetch('/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            hideLoading();
            if (data.success) {
                displayResults(data);
            } else {
                showAlert(data.error || 'An error occurred during analysis.', 'danger');
            }
        })
        .catch(error => {
            hideLoading();
            console.error('Error:', error);
            showAlert('An error occurred while analyzing the email. Please try again.', 'danger');
        });
    }

    function showLoading() {
        if (loadingSection) {
            loadingSection.style.display = 'block';
        }
        if (resultsSection) {
            resultsSection.style.display = 'none';
        }
        if (analyzeBtn) {
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
        }
        
        // Scroll to loading section
        if (loadingSection) {
            loadingSection.scrollIntoView({ behavior: 'smooth' });
        }
    }

    function hideLoading() {
        if (loadingSection) {
            loadingSection.style.display = 'none';
        }
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = '<i class="fas fa-search me-2"></i>Analyze Email';
        }
    }

    function displayResults(data) {
        const prediction = data.prediction;
        const individualPredictions = data.individual_predictions;
        const emailAnalysis = data.email_analysis;

        // Update result header
        const resultHeader = document.getElementById('resultHeader');
        const resultTitle = document.getElementById('resultTitle');
        const resultCard = document.getElementById('resultCard');

        if (prediction.prediction === 1) {
            resultHeader.className = 'card-header bg-danger text-white';
            resultTitle.innerHTML = '<i class="fas fa-exclamation-triangle me-2"></i>Phishing Email Detected!';
        } else {
            resultHeader.className = 'card-header bg-success text-white';
            resultTitle.innerHTML = '<i class="fas fa-check-circle me-2"></i>Legitimate Email';
        }

        // Display ensemble prediction
        displayEnsemblePrediction(prediction);

        // Display individual model predictions
        displayIndividualPredictions(individualPredictions);

        // Display email analysis
        displayEmailAnalysis(emailAnalysis);

        // Show results section
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    function displayEnsemblePrediction(prediction) {
        const ensembleResult = document.getElementById('ensembleResult');
        const ensembleLabel = document.getElementById('ensembleLabel');
        const ensembleDetails = document.getElementById('ensembleDetails');
        const confidenceBar = document.getElementById('confidenceBar');
        const confidenceText = document.getElementById('confidenceText');

        // Set alert class
        if (prediction.prediction === 1) {
            ensembleResult.className = 'alert alert-danger';
        } else {
            ensembleResult.className = 'alert alert-success';
        }

        // Update content
        ensembleLabel.textContent = prediction.label;
        ensembleDetails.textContent = `Model Agreement: ${prediction.votes} | ${prediction.agreement ? 'All models agree' : 'Mixed predictions'}`;

        // Update confidence bar
        const confidencePercent = (prediction.confidence * 100).toFixed(1);
        confidenceBar.style.width = confidencePercent + '%';
        confidenceBar.textContent = confidencePercent + '%';
        confidenceText.textContent = `Confidence: ${confidencePercent}%`;

        // Set progress bar color
        if (prediction.prediction === 1) {
            confidenceBar.className = 'progress-bar bg-danger';
        } else {
            confidenceBar.className = 'progress-bar bg-success';
        }
    }

    function displayIndividualPredictions(predictions) {
        const container = document.getElementById('individualPredictions');
        container.innerHTML = '';

        for (const [modelName, prediction] of Object.entries(predictions)) {
            const modelCard = document.createElement('div');
            modelCard.className = 'card mb-2';
            
            const cardClass = prediction.prediction === 1 ? 'border-danger' : 'border-success';
            modelCard.classList.add(cardClass);

            const modelTitle = modelName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            let confidenceInfo = '';
            if (prediction.probabilities) {
                const phishingProb = (prediction.probabilities.phishing * 100).toFixed(1);
                const legitimateProb = (prediction.probabilities.legitimate * 100).toFixed(1);
                confidenceInfo = `
                    <div class="mt-2">
                        <small class="text-muted">
                            Phishing: ${phishingProb}% | Legitimate: ${legitimateProb}%
                        </small>
                    </div>
                `;
            }

            modelCard.innerHTML = `
                <div class="card-body py-2">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <strong>${modelTitle}</strong>
                            <span class="badge ${prediction.prediction === 1 ? 'bg-danger' : 'bg-success'} ms-2">
                                ${prediction.label}
                            </span>
                            ${confidenceInfo}
                        </div>
                        <div class="col-md-4 text-end">
                            ${prediction.confidence ? 
                                `<span class="badge bg-secondary">Confidence: ${(prediction.confidence * 100).toFixed(1)}%</span>` : 
                                ''
                            }
                        </div>
                    </div>
                </div>
            `;

            container.appendChild(modelCard);
        }
    }

    function displayEmailAnalysis(analysis) {
        // Display statistics
        const statsContainer = document.getElementById('emailStats');
        const stats = analysis.statistics;
        
        statsContainer.innerHTML = `
            <div class="list-group">
                <div class="list-group-item d-flex justify-content-between">
                    <strong>Character Count:</strong>
                    <span>${stats.character_count || 0}</span>
                </div>
                <div class="list-group-item d-flex justify-content-between">
                    <strong>Word Count:</strong>
                    <span>${stats.word_count || 0}</span>
                </div>
                <div class="list-group-item d-flex justify-content-between">
                    <strong>URL Count:</strong>
                    <span>${stats.url_count || 0}</span>
                </div>
                <div class="list-group-item d-flex justify-content-between">
                    <strong>Sender:</strong>
                    <span class="text-truncate" style="max-width: 200px;">${stats.sender || 'Unknown'}</span>
                </div>
                <div class="list-group-item d-flex justify-content-between">
                    <strong>Risk Score:</strong>
                    <span class="badge ${analysis.risk_score > 70 ? 'bg-danger' : analysis.risk_score > 40 ? 'bg-warning' : 'bg-success'}">
                        ${analysis.risk_score || 0}/100
                    </span>
                </div>
            </div>
        `;

        // Display suspicious indicators
        const indicatorsContainer = document.getElementById('suspiciousIndicators');
        const indicators = analysis.suspicious_indicators || [];
        
        if (indicators.length > 0) {
            indicatorsContainer.innerHTML = `
                <div class="list-group">
                    ${indicators.map(indicator => `
                        <div class="list-group-item">
                            <i class="fas fa-exclamation-triangle text-warning me-2"></i>
                            ${indicator}
                        </div>
                    `).join('')}
                </div>
            `;
        } else {
            indicatorsContainer.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>
                    No suspicious indicators detected.
                </div>
            `;
        }
    }

    function showAlert(message, type) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        // Insert at the top of the container
        const container = document.querySelector('.container');
        container.insertBefore(alertDiv, container.firstChild);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    // Handle file upload progress (if on upload page)
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const fileSize = file.size;
                const maxSize = 16 * 1024 * 1024; // 16MB
                
                if (fileSize > maxSize) {
                    showAlert('File size exceeds 16MB limit.', 'danger');
                    fileInput.value = '';
                    return;
                }

                // Show file info
                const fileInfo = document.getElementById('fileInfo');
                if (fileInfo) {
                    fileInfo.innerHTML = `
                        <div class="alert alert-info">
                            <strong>Selected file:</strong> ${file.name} (${formatFileSize(fileSize)})
                        </div>
                    `;
                }
            }
        });
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Dashboard functionality
    if (window.location.pathname === '/dashboard') {
        loadDashboardData();
    }

    function loadDashboardData() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                updateDashboard(data);
            })
            .catch(error => {
                console.error('Error loading dashboard data:', error);
            });
    }

    function updateDashboard(data) {
        // Update statistics cards
        if (data.statistics) {
            updateStatsCards(data.statistics);
        }

        // Update recent predictions table
        if (data.recent_predictions) {
            updateRecentPredictions(data.recent_predictions);
        }

        // Update model performance
        if (data.model_performance) {
            updateModelPerformance(data.model_performance);
        }
    }

    function updateStatsCards(stats) {
        const elements = {
            'totalPredictions': stats.total_predictions || 0,
            'phishingDetected': stats.phishing_detected || 0,
            'legitimateEmails': stats.legitimate_emails || 0,
            'phishingRate': (stats.phishing_rate || 0).toFixed(1) + '%',
            'averageConfidence': (stats.average_confidence || 0).toFixed(3),
            'highRiskEmails': stats.high_risk_emails || 0
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        }
    }

    function updateRecentPredictions(predictions) {
        const tbody = document.getElementById('recentPredictionsBody');
        if (!tbody) return;

        tbody.innerHTML = '';
        
        predictions.forEach(pred => {
            const row = document.createElement('tr');
            const badgeClass = pred.prediction === 'Phishing' ? 'bg-danger' : 'bg-success';
            const riskClass = pred.risk_score > 70 ? 'bg-danger' : pred.risk_score > 40 ? 'bg-warning' : 'bg-success';
            
            row.innerHTML = `
                <td>${new Date(pred.timestamp).toLocaleString()}</td>
                <td class="text-truncate" style="max-width: 200px;">${pred.subject}</td>
                <td class="text-truncate" style="max-width: 150px;">${pred.sender}</td>
                <td><span class="badge ${badgeClass}">${pred.prediction}</span></td>
                <td>${(pred.confidence * 100).toFixed(1)}%</td>
                <td><span class="badge ${riskClass}">${pred.risk_score}/100</span></td>
            `;
            
            tbody.appendChild(row);
        });
    }

    function updateModelPerformance(performance) {
        const tbody = document.getElementById('modelPerformanceBody');
        if (!tbody) return;

        tbody.innerHTML = '';
        
        for (const [modelName, data] of Object.entries(performance)) {
            const row = document.createElement('tr');
            const modelTitle = modelName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            row.innerHTML = `
                <td>${modelTitle}</td>
                <td>${data.total_predictions}</td>
                <td>${data.phishing_detected}</td>
                <td>${data.phishing_rate}%</td>
                <td>${(data.average_confidence * 100).toFixed(1)}%</td>
            `;
            
            tbody.appendChild(row);
        }
    }
});