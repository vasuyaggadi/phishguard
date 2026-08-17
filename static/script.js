/* =====================================================
   PHISHGUARD - URL SCANNER
===================================================== */


const urlInput =
    document.getElementById("urlInput");

const scanButton =
    document.getElementById("scanButton");

const loading =
    document.getElementById("loading");

const errorBox =
    document.getElementById("error");

const result =
    document.getElementById("result");


/* =====================================================
   SCAN BUTTON
===================================================== */

scanButton.addEventListener(
    "click",
    function () {

        scanURL();

    }
);


/* =====================================================
   ENTER KEY
===================================================== */

urlInput.addEventListener(
    "keydown",
    function (event) {

        if (event.key === "Enter") {

            event.preventDefault();

            scanURL();

        }

    }
);


/* =====================================================
   SCAN URL
===================================================== */

async function scanURL() {

    const url =
        urlInput.value.trim();


    errorBox.textContent = "";


    if (!url) {

        errorBox.textContent =
            "Please enter a URL.";

        urlInput.focus();

        return;

    }


    scanButton.disabled = true;

    scanButton.textContent =
        "Scanning...";


    loading.classList.remove(
        "hidden"
    );


    result.classList.add(
        "hidden"
    );


    try {

        const response =
            await fetch(
                "/scan",
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

                            url: url

                        })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(

                data.error ||
                "Scan failed."

            );

        }


        displayResult(
            data
        );


    }


    catch (err) {

        console.error(
            "Scan error:",
            err
        );


        errorBox.textContent =
            err.message ||
            "Unable to scan URL.";

    }


    finally {

        scanButton.disabled = false;

        scanButton.textContent =
            "Scan URL";

        loading.classList.add(
            "hidden"
        );

    }

}


/* =====================================================
   DISPLAY RESULT
===================================================== */

function displayResult(data) {

    result.classList.remove(
        "hidden"
    );


    /* =================================================
       BASIC RESULT
    ================================================= */

    document.getElementById(
        "resultURL"
    ).textContent =
        data.url || "-";


    document.getElementById(
        "score"
    ).textContent =
        data.score ?? 0;


    document.getElementById(
        "risk"
    ).textContent =
        data.risk || "-";


    /* =================================================
       RISK CLASS
    ================================================= */

    const riskElement =
        document.getElementById(
            "risk"
        );


    riskElement.classList.remove(
        "risk-low",
        "risk-medium",
        "risk-high"
    );


    const riskText =
        String(
            data.risk || ""
        ).toLowerCase();


    if (riskText.includes("low")) {

        riskElement.classList.add(
            "risk-low"
        );

    }

    else if (
        riskText.includes("medium")
    ) {

        riskElement.classList.add(
            "risk-medium"
        );

    }

    else if (
        riskText.includes("high")
    ) {

        riskElement.classList.add(
            "risk-high"
        );

    }


    /* =================================================
       PROGRESS
    ================================================= */

    const score =
        Number(
            data.score
        ) || 0;


    document.getElementById(
        "progress"
    ).style.width =
        Math.min(
            score,
            100
        ) + "%";


    /* =================================================
       VIRUSTOTAL
    ================================================= */

    const vt =
        data.virustotal || {};


    document.getElementById(
        "malicious"
    ).textContent =
        vt.malicious ?? 0;


    document.getElementById(
        "suspicious"
    ).textContent =
        vt.suspicious ?? 0;


    document.getElementById(
        "undetected"
    ).textContent =
        vt.undetected ?? 0;


    document.getElementById(
        "vtStatus"
    ).textContent =
        vt.status ||
        "Analysis completed.";


    /* =================================================
       VENDORS
    ================================================= */

    const vendorsContainer =
        document.getElementById(
            "vendors"
        );


    vendorsContainer.innerHTML = "";


    const vendors =
        Array.isArray(
            data.vendors
        )
            ? data.vendors
            : [];


    if (
        vendors.length === 0
    ) {

        vendorsContainer.innerHTML =
            '<p class="empty-text">' +
            'No vendor information available.' +
            '</p>';

    }


    else {

        vendors.forEach(
            function (vendor) {

                const row =
                    document.createElement(
                        "div"
                    );


                row.className =
                    "vendor-row";


                const name =
                    document.createElement(
                        "div"
                    );


                name.className =
                    "vendor-name";


                name.textContent =
                    vendor.vendor ||
                    "Unknown Vendor";


                const vendorResult =
                    document.createElement(
                        "div"
                    );


                vendorResult.className =
                    "vendor-result";


                vendorResult.textContent =
                    vendor.result ||
                    "-";


                const category =
                    document.createElement(
                        "div"
                    );


                category.className =
                    "vendor-category";


                const categoryValue =
                    (
                        vendor.category ||
                        "undetected"
                    ).toLowerCase();


                category.textContent =
                    categoryValue;


                if (
                    categoryValue ===
                    "malicious"
                ) {

                    category.classList.add(
                        "vendor-malicious"
                    );

                }

                else if (
                    categoryValue ===
                    "suspicious"
                ) {

                    category.classList.add(
                        "vendor-suspicious"
                    );

                }

                else if (
                    categoryValue ===
                    "harmless"
                ) {

                    category.classList.add(
                        "vendor-harmless"
                    );

                }

                else {

                    category.classList.add(
                        "vendor-undetected"
                    );

                }


                row.appendChild(
                    name
                );

                row.appendChild(
                    vendorResult
                );

                row.appendChild(
                    category
                );


                vendorsContainer.appendChild(
                    row
                );

            }
        );

    }


    /* =================================================
       SERVING IP
    ================================================= */

    const ipContainer =
        document.getElementById(
            "servingIPs"
        );


    ipContainer.innerHTML = "";


    const servingIPs =
        Array.isArray(
            data.serving_ips
        )
            ? data.serving_ips
            : [];


    if (
        servingIPs.length === 0
    ) {

        ipContainer.innerHTML =
            '<p class="empty-text">' +
            'No serving IP found.' +
            '</p>';

    }


    else {

        servingIPs.forEach(
            function (ip) {

                const item =
                    document.createElement(
                        "div"
                    );


                item.className =
                    "ip-item";


                item.textContent =
                    ip;


                ipContainer.appendChild(
                    item
                );

            }
        );

    }


    /* =================================================
       HISTORY
    ================================================= */

    const history =
        data.history || {};


    document.getElementById(
        "timesSubmitted"
    ).textContent =
        history.times_submitted ??
        "-";


    document.getElementById(
        "firstSubmission"
    ).textContent =
        formatDate(
            history.first_submission_date
        );


    document.getElementById(
        "lastSubmission"
    ).textContent =
        formatDate(
            history.last_submission_date
        );


    /* =================================================
       PAGE STATS
    ================================================= */

    const pageStats =
        data.page_stats || {};


    document.getElementById(
        "pageTitle"
    ).textContent =
        pageStats.title ||
        "-";


    document.getElementById(
        "reputation"
    ).textContent =
        pageStats.reputation ??
        "-";


    document.getElementById(
        "httpCode"
    ).textContent =
        pageStats.last_http_response_code ??
        "-";


    const categories =
        Array.isArray(
            pageStats.categories
        )
            ? pageStats.categories
            : [];


    document.getElementById(
        "categories"
    ).textContent =
        categories.length > 0
            ? categories.join(", ")
            : "-";


    document.getElementById(
        "finalURL"
    ).textContent =
        pageStats.final_url ||
        "-";


    const outgoingLinks =
        Array.isArray(
            pageStats.outgoing_links
        )
            ? pageStats.outgoing_links
            : [];


    document.getElementById(
        "outgoingLinks"
    ).textContent =
        outgoingLinks.length;


    /* =================================================
       LOCAL DETECTION
    ================================================= */

    const reasonList =
        document.getElementById(
            "reasons"
        );


    reasonList.innerHTML = "";


    const reasons =
        Array.isArray(
            data.reasons
        )
            ? data.reasons
            : [];


    if (
        reasons.length === 0
    ) {

        const li =
            document.createElement(
                "li"
            );


        li.textContent =
            "No obvious phishing indicators were detected.";


        reasonList.appendChild(
            li
        );

    }


    else {

        reasons.forEach(
            function (reason) {

                const li =
                    document.createElement(
                        "li"
                    );


                li.textContent =
                    reason;


                reasonList.appendChild(
                    li
                );

            }
        );

    }


    /* =================================================
       SCROLL TO RESULT
    ================================================= */

    result.scrollIntoView({

        behavior: "smooth",

        block: "start"

    });

}


/* =====================================================
   FORMAT DATE
===================================================== */

function formatDate(timestamp) {

    if (

        timestamp === null ||

        timestamp === undefined ||

        timestamp === "" ||

        timestamp === "-"

    ) {

        return "-";

    }


    const number =
        Number(
            timestamp
        );


    if (

        Number.isNaN(number) ||

        number <= 0

    ) {

        return "-";

    }


    return new Date(
        number * 1000
    ).toLocaleString();

}