document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    const threatLog = document.getElementById("threatLog");

    if (loginForm) {
        loginForm.addEventListener("submit", handleLogin);
    }

    if (registerForm) {
        registerForm.addEventListener("submit", handleRegister);
    }

    if (threatLog) {
        loadThreatLog();
    }
});


async function handleLogin(event) {
    event.preventDefault();

    const formData = new FormData(event.target);

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (data.blocked) {
            showAlert(
                `${data.message}: ${data.reason}`,
                "warning"
            );
            return;
        }

        if (data.success) {
            showAlert(data.message, "success");

            setTimeout(() => {
                window.location.href = "/dashboard";
            }, 800);

            return;
        }

        showAlert(data.message, "danger");

    } catch (error) {
        console.error("Login error:", error);
        showAlert("Unable to connect to the server.", "danger");
    }
}


async function handleRegister(event) {
    event.preventDefault();

    const formData = new FormData(event.target);

    try {
        const response = await fetch("/api/register", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (data.blocked) {
            showAlert(
                `${data.message}: ${data.reason}`,
                "warning"
            );
            return;
        }

        if (data.success) {
            showAlert(data.message, "success");

            setTimeout(() => {
                window.location.href = "/";
            }, 800);

            return;
        }

        showAlert(data.message, "danger");

    } catch (error) {
        console.error("Registration error:", error);
        showAlert("Unable to connect to the server.", "danger");
    }
}


async function loadThreatLog() {
    const threatLog = document.getElementById("threatLog");

    try {
        const response = await fetch("/api/threat-log");
        const data = await response.json();

        threatLog.innerHTML = "";

        if (!data.threats || data.threats.length === 0) {
            threatLog.innerHTML = `
                <tr>
                    <td colspan="4">No threats detected.</td>
                </tr>
            `;
            return;
        }

        data.threats
            .slice()
            .reverse()
            .forEach((threat) => {
                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${escapeHtml(formatAttackType(threat.attack_type))}</td>
                    <td>${escapeHtml(threat.payload || "")}</td>
                    <td>${escapeHtml(threat.ip || "unknown")}</td>
                    <td>${escapeHtml(threat.timestamp || "")}</td>
                `;

                threatLog.appendChild(row);
            });

    } catch (error) {
        console.error("Threat log error:", error);

        threatLog.innerHTML = `
            <tr>
                <td colspan="4">Unable to load threat log.</td>
            </tr>
        `;

        showAlert("Failed to load threat log.", "danger");
    }
}


function showAlert(message, type) {
    const alertBox = document.getElementById("alertBox");

    if (!alertBox) {
        return;
    }

    alertBox.innerHTML = "";

    const alert = document.createElement("div");
    alert.className = `alert-${type}`;
    alert.textContent = message;

    alertBox.appendChild(alert);
}


function formatAttackType(type) {
    const attackTypes = {
        sqli: "SQL Injection",
        xss: "Cross-Site Scripting (XSS)",
        cmdi: "Command Injection"
    };

    return attackTypes[type] || type || "Unknown";
}


function escapeHtml(value) {
    const element = document.createElement("div");
    element.textContent = String(value);
    return element.innerHTML;
}