const targetInput =
    document.getElementById(
        "targetInput"
    );

const scanButton =
    document.getElementById(
        "scanButton"
    );

const checkButton =
    document.getElementById(
        "checkButton"
    );

const scanStatus =
    document.getElementById(
        "scanStatus"
    );

let verifiedTarget = null;


targetInput.addEventListener(
    "input",
    function () {

        verifiedTarget = null;

        scanButton.disabled = true;

        document
            .getElementById(
                "preflightPanel"
            )
            .classList.add(
                "hidden"
            );

    }
);


targetInput.addEventListener(
    "keydown",
    function (event) {

        if (event.key === "Enter") {

            if (verifiedTarget) {
                startScan();
            }
            else {
                checkTarget();
            }

        }

    }
);


async function checkTarget() {

    const target =
        targetInput.value.trim();

    if (!target) {

        showStatus(
            "Enter an authorized target first.",
            true
        );

        return;
    }


    checkButton.disabled = true;

    scanButton.disabled = true;

    checkButton.textContent =
        "Checking...";


    showStatus(
        "Checking DNS and web availability...",
        false
    );


    try {

        const response = await fetch(
            "/api/preflight",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    target
                })
            }
        );


        const result =
            await response.json();


        if (
            !response.ok
            || !result.success
        ) {

            throw new Error(
                result.error ||
                "Target check failed."
            );
        }


        renderPreflight(
            result.preflight
        );


        if (
            result.preflight
                .continue_recon
        ) {

            verifiedTarget =
                result.target.hostname;

            scanButton.disabled =
                false;


            showStatus(
                "Target is available. Reconnaissance can begin.",
                false
            );

        }

        else {

            verifiedTarget = null;

            scanButton.disabled =
                true;


            showStatus(
                result.preflight.message,
                true
            );

        }

    }

    catch (error) {

        verifiedTarget = null;

        scanButton.disabled = true;

        showStatus(
            error.message,
            true
        );

    }

    finally {

        checkButton.disabled = false;

        checkButton.textContent =
            "Check Target";

    }

}


function renderPreflight(
    preflight
) {

    const panel =
        document.getElementById(
            "preflightPanel"
        );


    panel.classList.remove(
        "hidden"
    );


    const statusElement =
        document.getElementById(
            "targetStatus"
        );


    statusElement.textContent =
        preflight.status;


    statusElement.className =
        (
            preflight.continue_recon
                ? "status-active"
                : "status-inactive"
        );


    document
        .getElementById(
            "dnsStatus"
        )
        .textContent =
        preflight.dns?.success
            ? "Resolved"
            : "Failed";


    let webStatus =
        "Unavailable";


    if (
        preflight.https
        && preflight.https.responding
    ) {

        webStatus =
            `HTTPS ${preflight.https.status_code}`;

    }

    else if (
        preflight.http
        && preflight.http.responding
    ) {

        webStatus =
            `HTTP ${preflight.http.status_code}`;

    }


    document
        .getElementById(
            "webStatus"
        )
        .textContent =
        webStatus;
}


async function startScan() {

    const target =
        targetInput.value.trim();


    if (!target) {

        showStatus(
            "Enter an authorized target.",
            true
        );

        return;
    }


    if (!verifiedTarget) {

        showStatus(
            "Check the target before starting reconnaissance.",
            true
        );

        return;
    }


    setScanningState(
        true
    );


    showStatus(
        "ReconForge is collecting reconnaissance data...",
        false
    );


    try {

        const response = await fetch(
            "/api/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    target
                })
            }
        );


        const result =
            await response.json();


        if (
            !response.ok
            || !result.success
        ) {

            throw new Error(
                result.error ||
                "Reconnaissance failed."
            );
        }


        renderResults(
            result
        );


        showStatus(
            "Reconnaissance completed successfully.",
            false
        );

    }

    catch (error) {

        showStatus(
            error.message,
            true
        );

    }

    finally {

        setScanningState(
            false
        );

    }

}


function setScanningState(
    scanning
) {

    targetInput.disabled =
        scanning;

    checkButton.disabled =
        scanning;

    scanButton.disabled =
        scanning;


    scanButton.textContent =
        scanning
            ? "Scanning..."
            : "Start Recon";


    if (
        !scanning
        && verifiedTarget
    ) {

        scanButton.disabled =
            false;

    }

}


function showStatus(
    message,
    isError
) {

    scanStatus.classList.remove(
        "hidden",
        "error"
    );


    if (isError) {

        scanStatus.classList.add(
            "error"
        );

    }


    scanStatus.textContent =
        message;
}


function renderResults(
    result
) {

    renderSummary(
        result.scan
    );

    renderModules(
        result.modules
    );

    renderTarget(
        result.target
    );

    renderObservations(
        result.observations
    );

    renderReports(
        result.reports
    );


    document
        .getElementById(
            "summarySection"
        )
        .classList.remove(
            "hidden"
        );


    document
        .getElementById(
            "resultsSection"
        )
        .classList.remove(
            "hidden"
        );


    document
        .getElementById(
            "findingsSection"
        )
        .classList.remove(
            "hidden"
        );


    document
        .getElementById(
            "reportSection"
        )
        .classList.remove(
            "hidden"
        );
}


function renderSummary(
    scan
) {

    const severity =
        scan.severity_summary || {};


    document
        .getElementById(
            "moduleCount"
        )
        .textContent =
        scan.module_summary?.total || 0;


    document
        .getElementById(
            "observationCount"
        )
        .textContent =
        scan.total_observations || 0;


    document
        .getElementById(
            "highCount"
        )
        .textContent =
        severity.High || 0;


    document
        .getElementById(
            "mediumCount"
        )
        .textContent =
        severity.Medium || 0;


    document
        .getElementById(
            "lowCount"
        )
        .textContent =
        severity.Low || 0;
}


function renderModules(
    modules
) {

    const container =
        document.getElementById(
            "moduleList"
        );


    container.innerHTML = "";


    Object.entries(
        modules
    ).forEach(
        ([name, result]) => {

            const status =
                result.status ||
                "unknown";


            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "module-item";


            item.innerHTML = `

                <span class="module-name">
                    ${escapeHtml(name)}
                </span>

                <span
                    class="
                        module-status
                        ${escapeHtml(status)}
                    "
                >
                    ${escapeHtml(status)}
                </span>

            `;


            container.appendChild(
                item
            );

        }
    );
}


function renderTarget(
    target
) {

    const container =
        document.getElementById(
            "targetDetails"
        );


    const rows = [

        [
            "Original",
            target.original
        ],

        [
            "Hostname",
            target.hostname
        ],

        [
            "HTTPS",
            target.https_url
        ],

        [
            "HTTP",
            target.http_url
        ],

        [
            "Input Scheme",
            target.input_scheme
        ],

        [
            "IP Target",
            target.is_ip
                ? "Yes"
                : "No"
        ]

    ];


    container.innerHTML =
        rows.map(
            ([name, value]) => `

                <div class="detail-row">

                    <span>
                        ${escapeHtml(name)}
                    </span>

                    <strong>
                        ${escapeHtml(
                            value ?? "Unavailable"
                        )}
                    </strong>

                </div>

            `
        ).join("");
}


function renderObservations(
    observations
) {

    const container =
        document.getElementById(
            "findingsList"
        );


    container.innerHTML = "";


    if (!observations.length) {

        container.innerHTML = `
            <p>
                No reconnaissance observations
                were generated.
            </p>
        `;

        return;
    }


    observations.forEach(
        observation => {

            const severity =
                (
                    observation.severity
                    || "Informational"
                ).toLowerCase();


            const item =
                document.createElement(
                    "article"
                );


            item.className =
                "finding";


            item.innerHTML = `

                <div class="finding-top">

                    <div class="finding-title">

                        <span class="finding-id">
                            ${escapeHtml(
                                observation.id
                            )}
                        </span>

                        <strong>
                            ${escapeHtml(
                                observation.title
                            )}
                        </strong>

                    </div>


                    <span
                        class="
                            severity
                            ${escapeHtml(severity)}
                        "
                    >

                        ${escapeHtml(
                            observation.severity
                        )}

                    </span>

                </div>


                <p>

                    <strong>
                        Module:
                    </strong>

                    ${escapeHtml(
                        observation.source_module
                        || "Unknown"
                    )}

                </p>


                <p>

                    <strong>
                        Evidence:
                    </strong>

                    ${escapeHtml(
                        observation.evidence
                        || "Unavailable"
                    )}

                </p>


                <p>

                    <strong>
                        Description:
                    </strong>

                    ${escapeHtml(
                        observation.description
                        || ""
                    )}

                </p>


                <p>

                    <strong>
                        Recommendation:
                    </strong>

                    ${escapeHtml(
                        observation.recommendation
                        || ""
                    )}

                </p>

            `;


            container.appendChild(
                item
            );

        }
    );
}


function renderReports(
    reports
) {

    const htmlButton =
        document.getElementById(
            "htmlButton"
        );

    const pdfButton =
        document.getElementById(
            "pdfButton"
        );

    const jsonButton =
        document.getElementById(
            "jsonButton"
        );


    if (reports.html) {

        htmlButton.href =
            reports.html;

        htmlButton.style.display =
            "inline-flex";

    }

    else {

        htmlButton.style.display =
            "none";

    }


    if (reports.pdf) {

        pdfButton.href =
            reports.pdf;

        pdfButton.style.display =
            "inline-flex";

    }

    else {

        pdfButton.style.display =
            "none";

    }


    if (reports.json) {

        jsonButton.href =
            reports.json;

        jsonButton.style.display =
            "inline-flex";

    }

    else {

        jsonButton.style.display =
            "none";

    }

}


function escapeHtml(
    value
) {

    if (
        value === null
        || value === undefined
    ) {

        return "";

    }


    return String(
        value
    )
        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );
}