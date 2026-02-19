#include "crow.h"
#include <string>
#include <cpr/cpr.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <jwt-cpp/jwt.h>
#include <chrono>
#include <random>

const std::string SUPABASE_URL =
    "https://uavcodnqypzxrvffkmqf.supabase.co/rest/v1";

// ================= SHA256 =================
std::string sha256(const std::string &str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2)
           << std::setfill('0') << (int)hash[i];
    return ss.str();
}

// ================= RANDOM TOKEN =================
std::string generate_token(size_t length = 32)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    return oss.str();
}

// ================= SEND EMAIL via Gmail SMTP =================
bool send_email(const std::string &to,
                const std::string &subject,
                const std::string &html_body)
{
    const char *gmail_user = std::getenv("GMAIL_USER");
    const char *gmail_pass = std::getenv("GMAIL_APP_PASSWORD");
    if (!gmail_user || !gmail_pass) {
        std::cerr << "GMAIL_USER or GMAIL_APP_PASSWORD not set!" << std::endl;
        return false;
    }

    // Build raw email message
    std::string message =
        "From: CampusForge <" + std::string(gmail_user) + ">\r\n"
        "To: " + to + "\r\n"
        "Subject: " + subject + "\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "\r\n" +
        html_body;

    struct upload_status {
        const std::string *data;
        size_t offset;
    };

    upload_status upload_ctx = {&message, 0};

    CURL *curl = curl_easy_init();
    if (!curl) return false;

    struct curl_slist *recipients = nullptr;
    recipients = curl_slist_append(recipients, to.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
    curl_easy_setopt(curl, CURLOPT_USERNAME, gmail_user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, gmail_pass);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, gmail_user);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION,
        +[](char *ptr, size_t size, size_t nmemb, void *userp) -> size_t {
            auto *u = static_cast<upload_status*>(userp);
            size_t room = size * nmemb;
            size_t len  = u->data->size() - u->offset;
            if (len == 0) return 0;
            size_t copy = std::min(room, len);
            memcpy(ptr, u->data->c_str() + u->offset, copy);
            u->offset += copy;
            return copy;
        });
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: "
                  << curl_easy_strerror(res) << std::endl;
        return false;
    }
    return true;
}

// ================= VALIDATION =================
bool is_valid_status(const std::string &status)
{
    return status == "live" || status == "expired";
}

// ================= JSON ESCAPE =================
std::string escape_json(const std::string &str)
{
    std::string result;
    for (char c : str)
    {
        if (c == '"')
            result += "\\\"";
        else if (c == '\\')
            result += "\\\\";
        else if (c == '\n')
            result += "\\n";
        else if (c == '\r')
            result += "\\r";
        else if (c == '\t')
            result += "\\t";
        else
            result += c;
    }
    return result;
}

// ================= CORS =================
struct CORSMiddleware
{
    struct context
    {
    };

    void before_handle(crow::request &req,
                       crow::response &res,
                       context &)
    {
        const char *fe = std::getenv("FRONTEND_URL");
        std::string origin = fe ? fe : "http://localhost:5173";

        res.set_header("Access-Control-Allow-Origin", origin);
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.set_header("Access-Control-Max-Age", "86400");

        if (req.method == crow::HTTPMethod::OPTIONS)
        {
            res.code = 204;
            res.end();
            return;
        }
    }

    void after_handle(crow::request &,
                      crow::response &res,
                      context &)
    {
        const char *fe = std::getenv("FRONTEND_URL");
        std::string origin = fe ? fe : "http://localhost:5173";

        res.set_header("Access-Control-Allow-Origin", origin);
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }
};

// ================= AUTH =================
struct AuthMiddleware
{
    struct context
    {
        std::string user_email;
    };

    void before_handle(crow::request &req,
                       crow::response &res,
                       context &ctx)
    {
        if (req.method == crow::HTTPMethod::OPTIONS)
            return;

        if (req.url == "/" ||
            req.url == "/signup" ||
            req.url == "/login" ||
            req.url == "/forgot-password" ||
            req.url == "/reset-password" ||
            req.url == "/verify-email" ||
            req.url.rfind("/projects", 0) == 0)
            return;

        auto authHeader = req.get_header_value("Authorization");

        if (authHeader.empty() || authHeader.substr(0, 7) != "Bearer ")
        {
            res.code = 401;
            res.write("Unauthorized");
            res.end();
            return;
        }

        std::string token = authHeader.substr(7);
        const char *secret = std::getenv("JWT_SECRET");

        try
        {
            auto decoded = jwt::decode(token);
            jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{secret})
                .with_issuer("CampusConnect")
                .verify(decoded);

            ctx.user_email =
                decoded.get_payload_claim("email").as_string();
        }
        catch (...)
        {
            res.code = 401;
            res.write("Invalid token");
            res.end();
            return;
        }
    }

    void after_handle(crow::request &, crow::response &, context &) {}
};


int main()
{

    curl_global_init(CURL_GLOBAL_DEFAULT);

    const char *key = std::getenv("SUPABASE_KEY");
    if (!key)
    {
        std::cerr << "SUPABASE_KEY not set!" << std::endl;
        return 1;
    }

    std::string API_KEY = key;
    crow::App<CORSMiddleware, AuthMiddleware> app;

    CROW_ROUTE(app, "/")([]()
                         { return "CampusConnect Backend Running!"; });

    // ================= SIGNUP =================
    CROW_ROUTE(app, "/signup").methods("POST"_method)([API_KEY](const crow::request &req)
                                                      {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string email     = body["email"].s();
        std::string full_name = body["full_name"].s();
        std::string hashed    = sha256(body["password"].s());

        std::string jsonBody =
            "{\"full_name\":\"" + escape_json(full_name) +
            "\",\"email\":\""   + escape_json(email) +
            "\",\"password\":\"" + hashed + "\"}";

        auto r = cpr::Post(
            cpr::Url{SUPABASE_URL + "/users"},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{jsonBody});

        if (r.status_code == 201)
        {
            auto ur = cpr::Get(
                cpr::Url{SUPABASE_URL + "/users?email=eq." + email + "&select=id"},
                cpr::Header{
                    {"apikey", API_KEY},
                    {"Authorization", "Bearer " + API_KEY}});

            auto ujson = crow::json::load(ur.text);
            if (ujson && ujson.size() > 0)
            {
                int user_id = ujson[0]["id"].i();

                std::string token = generate_token();
                std::string vtBody =
                    "{\"user_id\":" + std::to_string(user_id) +
                    ",\"token\":\"" + token + "\"}";

                cpr::Post(
                    cpr::Url{SUPABASE_URL + "/email_verifications"},
                    cpr::Header{
                        {"apikey", API_KEY},
                        {"Authorization", "Bearer " + API_KEY},
                        {"Content-Type", "application/json"},
                        {"Prefer", "return=minimal"}},
                    cpr::Body{vtBody});

                const char *fe = std::getenv("FRONTEND_URL");
                std::string frontend_url = fe ? fe : "http://localhost:5173";
                std::string link = frontend_url + "/verify-email?token=" + token;

                std::string html =
                    "<h2>Welcome to CampusForge, " + escape_json(full_name) + "!</h2>"
                    "<p>Click the button below to verify your email address.</p>"
                    "<a href=\"" + link + "\" style=\"background:#4f46e5;color:white;"
                    "padding:12px 24px;border-radius:6px;text-decoration:none;"
                    "display:inline-block;font-family:sans-serif\">Verify Email</a>"
                    "<p style=\"color:#888\">This link expires in 24 hours.</p>";

                send_email(email, "Verify your CampusForge email", html);
            }
        }

        return crow::response(r.status_code, r.text); });

    // ================= LOGIN =================
    CROW_ROUTE(app, "/login").methods("POST"_method)([API_KEY](const crow::request &req)
                                                     {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string email    = body["email"].s();
        std::string password = body["password"].s();

        auto r = cpr::Get(
            cpr::Url{SUPABASE_URL + "/users?email=eq." + email},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY}});

        auto json = crow::json::load(r.text);
        if (!json || json.size() == 0)
            return crow::response(400, "User not found");

        if (json[0]["password"].s() != sha256(password))
            return crow::response(400, "Incorrect password");

        const char *secret = std::getenv("JWT_SECRET");
        if (!secret)
        {
            return crow::response(500, "JWT_SECRET not set");
        }

        auto token = jwt::create()
            .set_issuer("CampusConnect")
            .set_payload_claim("email", jwt::claim(email))
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
            .sign(jwt::algorithm::hs256{secret});

        crow::json::wvalue result;
        result["token"]     = token;
        result["full_name"] = std::string(json[0]["full_name"].s());
        result["email"]     = email;

        return crow::response(result); });

    // ================= VERIFY EMAIL =================
    CROW_ROUTE(app, "/verify-email").methods("GET"_method)([API_KEY](const crow::request &req)
                                                           {
        auto token_param = req.url_params.get("token");
        if (!token_param)
            return crow::response(400, "{\"error\":\"Token required\"}");

        std::string token = token_param;

        auto now_tp = std::chrono::system_clock::now();
        auto now_t  = std::chrono::system_clock::to_time_t(now_tp);
        std::tm tm_utc{};
#ifdef _WIN32
        gmtime_s(&tm_utc, &now_t);
#else
        gmtime_r(&now_t, &tm_utc);
#endif
        char now_buf[32];
        std::strftime(now_buf, sizeof(now_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
        std::string now_str(now_buf);

        auto tr = cpr::Get(
            cpr::Url{SUPABASE_URL + "/email_verifications"
                     "?token=eq." + token +
                     "&used=eq.false"
                     "&expires_at=gte." + now_str +
                     "&select=id,user_id"},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY}});

        auto rows = crow::json::load(tr.text);
        if (!rows || rows.size() == 0)
            return crow::response(400, "{\"error\":\"Invalid or expired token\"}");

        int row_id  = rows[0]["id"].i();
        int user_id = rows[0]["user_id"].i();

        cpr::Patch(
            cpr::Url{SUPABASE_URL + "/email_verifications?id=eq." + std::to_string(row_id)},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{"{\"used\":true}"});

        cpr::Patch(
            cpr::Url{SUPABASE_URL + "/users?id=eq." + std::to_string(user_id)},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{"{\"email_verified\":true}"});

        return crow::response(200, "{\"message\":\"Email verified successfully\"}"); });

    // ================= FORGOT PASSWORD =================
    CROW_ROUTE(app, "/forgot-password").methods("POST"_method)([API_KEY](const crow::request &req)
                                                               {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string email = body["email"].s();

        auto ur = cpr::Get(
            cpr::Url{SUPABASE_URL + "/users?email=eq." + email + "&select=id"},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY}});

        auto users = crow::json::load(ur.text);
        if (users && users.size() > 0)
        {
            int user_id = users[0]["id"].i();

            cpr::Patch(
                cpr::Url{SUPABASE_URL + "/password_resets"
                         "?user_id=eq." + std::to_string(user_id) +
                         "&used=eq.false"},
                cpr::Header{
                    {"apikey", API_KEY},
                    {"Authorization", "Bearer " + API_KEY},
                    {"Content-Type", "application/json"},
                    {"Prefer", "return=minimal"}},
                cpr::Body{"{\"used\":true}"});

            std::string token = generate_token();
            std::string prBody =
                "{\"user_id\":" + std::to_string(user_id) +
                ",\"token\":\"" + token + "\"}";

            cpr::Post(
                cpr::Url{SUPABASE_URL + "/password_resets"},
                cpr::Header{
                    {"apikey", API_KEY},
                    {"Authorization", "Bearer " + API_KEY},
                    {"Content-Type", "application/json"},
                    {"Prefer", "return=minimal"}},
                cpr::Body{prBody});

            const char *fe = std::getenv("FRONTEND_URL");
            std::string frontend_url = fe ? fe : "http://localhost:5173";
            std::string link = frontend_url + "/reset-password?token=" + token;

            std::string html =
                "<h2>Reset your CampusForge password</h2>"
                "<p>We received a password reset request for your account.</p>"
                "<a href=\"" + link + "\" style=\"background:#4f46e5;color:white;"
                "padding:12px 24px;border-radius:6px;text-decoration:none;"
                "display:inline-block;font-family:sans-serif\">Reset Password</a>"
                "<p style=\"color:#888\">This link expires in 1 hour. "
                "If you did not request this, you can safely ignore it.</p>";

            send_email(email, "Reset your CampusForge password", html);
        }

        return crow::response(200,
            "{\"message\":\"If that email exists, a reset link has been sent\"}"); });

    // ================= RESET PASSWORD =================
    CROW_ROUTE(app, "/reset-password").methods("POST"_method)([API_KEY](const crow::request &req)
                                                              {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string token        = body["token"].s();
        std::string new_password = body["new_password"].s();

        if (new_password.size() < 8)
            return crow::response(400, "{\"error\":\"Password must be at least 8 characters\"}");

        auto now_tp2 = std::chrono::system_clock::now();
        auto now_t2  = std::chrono::system_clock::to_time_t(now_tp2);
        std::tm tm_utc2{};
#ifdef _WIN32
        gmtime_s(&tm_utc2, &now_t2);
#else
        gmtime_r(&now_t2, &tm_utc2);
#endif
        char now_buf2[32];
        std::strftime(now_buf2, sizeof(now_buf2), "%Y-%m-%dT%H:%M:%SZ", &tm_utc2);
        std::string now_str2(now_buf2);

        auto tr = cpr::Get(
            cpr::Url{SUPABASE_URL + "/password_resets"
                     "?token=eq." + token +
                     "&used=eq.false"
                     "&expires_at=gte." + now_str2 +
                     "&select=id,user_id"},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY}});

        auto rows = crow::json::load(tr.text);
        if (!rows || rows.size() == 0)
            return crow::response(400, "{\"error\":\"Invalid or expired token\"}");

        int row_id  = rows[0]["id"].i();
        int user_id = rows[0]["user_id"].i();

        std::string hashed = sha256(new_password);

        cpr::Patch(
            cpr::Url{SUPABASE_URL + "/users?id=eq." + std::to_string(user_id)},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{"{\"password\":\"" + hashed + "\"}"});

        cpr::Patch(
            cpr::Url{SUPABASE_URL + "/password_resets?id=eq." + std::to_string(row_id)},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{"{\"used\":true}"});

        return crow::response(200, "{\"message\":\"Password reset successfully\"}"); });

    // ================= ADD PROJECT =================
    CROW_ROUTE(app, "/add_project").methods("POST"_method)([API_KEY, &app](const crow::request &req)
                                                           {
        auto& ctx = app.get_context<AuthMiddleware>(req);
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        if (!is_valid_status(body["status"].s()))
            return crow::response(400, "Invalid status");

        bool has_contact_no = body.has("contact_no") && body["contact_no"].i() != 0;
        int64_t contact_no  = has_contact_no ? body["contact_no"].i() : 0;

        int team_size = body.has("team_size") ? body["team_size"].i() : 0;

        std::string contact_name = body.has("contact_name")
            ? escape_json(std::string(body["contact_name"].s())) : "";
        std::string contact_email = body.has("contact_email")
            ? escape_json(std::string(body["contact_email"].s())) : "";

        std::string categoryJson = "[";
        if (body.has("category") && body["category"].t() == crow::json::type::List) {
            auto arr = body["category"];
            for (size_t ci = 0; ci < arr.size(); ci++) {
                if (ci > 0) categoryJson += ",";
                categoryJson += "\"" + escape_json(std::string(arr[ci].s())) + "\"";
            }
        }
        categoryJson += "]";

        std::string jsonBody =
            "{"
            "\"title\":\""         + escape_json(std::string(body["title"].s()))       + "\","
            "\"description\":\""   + escape_json(std::string(body["description"].s())) + "\","
            "\"skills\":\""        + escape_json(std::string(body["skills"].s()))       + "\","
            "\"category\":"        + categoryJson                                        + ","
            "\"team_size\":"       + std::to_string(team_size)                          + ","
            "\"status\":\""        + escape_json(std::string(body["status"].s()))       + "\","
            "\"contact_no\":"      + (has_contact_no ? std::to_string(contact_no) : "null") + ","
            "\"contact_name\":\""  + contact_name                                        + "\","
            "\"contact_email\":\"" + contact_email                                       + "\","
            "\"owner_email\":\""   + ctx.user_email                                     + "\""
            "}";

        auto r = cpr::Post(
            cpr::Url{SUPABASE_URL + "/projects"},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{jsonBody});

        return crow::response(r.status_code, r.text); });

    // ================= GET PROJECTS =================
    CROW_ROUTE(app, "/projects").methods("GET"_method)([API_KEY](const crow::request &req)
                                                       {
        std::string search = "";
        std::string status = "";

        if (req.url_params.get("search"))
            search = "&title=ilike.*" +
                     std::string(req.url_params.get("search")) + "*";

        if (req.url_params.get("status"))
            status = "&status=eq." +
                     std::string(req.url_params.get("status"));

        std::string url = SUPABASE_URL + "/projects?select=*" + search + status;

        auto r = cpr::Get(
            cpr::Url{url},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Range-Unit", "items"},
                {"Range", "0-999"}});

        return crow::response(r.status_code, r.text); });

    // ================= MY PROJECTS =================
    CROW_ROUTE(app, "/my_projects").methods("GET"_method)([API_KEY, &app](const crow::request &req)
                                                          {
        auto& ctx = app.get_context<AuthMiddleware>(req);

        auto r = cpr::Get(
            cpr::Url{SUPABASE_URL + "/projects?owner_email=eq." + ctx.user_email},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY}});

        return crow::response(r.status_code, r.text); });

    // ================= EDIT PROJECT =================
    CROW_ROUTE(app, "/edit_project").methods("PUT"_method)([API_KEY, &app](const crow::request &req)
                                                           {
        auto& ctx = app.get_context<AuthMiddleware>(req);
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        int id = body["id"].i();

        if (!is_valid_status(body["status"].s()))
            return crow::response(400, "Invalid status");

        bool has_contact_no = body.has("contact_no") && body["contact_no"].i() != 0;
        int64_t contact_no  = has_contact_no ? body["contact_no"].i() : 0;

        int team_size = body.has("team_size") ? body["team_size"].i() : 0;

        std::string contact_name = body.has("contact_name")
            ? escape_json(std::string(body["contact_name"].s())) : "";
        std::string contact_email = body.has("contact_email")
            ? escape_json(std::string(body["contact_email"].s())) : "";

        std::string categoryJson = "[";
        if (body.has("category") && body["category"].t() == crow::json::type::List) {
            auto arr = body["category"];
            for (size_t ci = 0; ci < arr.size(); ci++) {
                if (ci > 0) categoryJson += ",";
                categoryJson += "\"" + escape_json(std::string(arr[ci].s())) + "\"";
            }
        }
        categoryJson += "]";

        std::string jsonBody =
            "{"
            "\"title\":\""         + escape_json(std::string(body["title"].s()))       + "\","
            "\"description\":\""   + escape_json(std::string(body["description"].s())) + "\","
            "\"skills\":\""        + escape_json(std::string(body["skills"].s()))       + "\","
            "\"category\":"        + categoryJson                                        + ","
            "\"team_size\":"       + std::to_string(team_size)                          + ","
            "\"status\":\""        + escape_json(std::string(body["status"].s()))       + "\","
            "\"contact_no\":"      + (has_contact_no ? std::to_string(contact_no) : "null") + ","
            "\"contact_name\":\""  + contact_name                                        + "\","
            "\"contact_email\":\"" + contact_email                                       + "\""
            "}";

        std::string url =
            SUPABASE_URL +
            "/projects?id=eq." + std::to_string(id) +
            "&owner_email=eq." + ctx.user_email;

        auto r = cpr::Patch(
            cpr::Url{url},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Content-Type", "application/json"},
                {"Prefer", "return=minimal"}},
            cpr::Body{jsonBody});

        return crow::response(r.status_code, r.text); });

    // ================= DELETE PROJECT =================
    CROW_ROUTE(app, "/delete_project").methods("DELETE"_method)([API_KEY, &app](const crow::request &req)
                                                                {
        auto& ctx = app.get_context<AuthMiddleware>(req);
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        int id = body["id"].i();

        std::string url =
            SUPABASE_URL +
            "/projects?id=eq." + std::to_string(id) +
            "&owner_email=eq." + ctx.user_email;

        auto r = cpr::Delete(
            cpr::Url{url},
            cpr::Header{
                {"apikey", API_KEY},
                {"Authorization", "Bearer " + API_KEY},
                {"Prefer", "return=minimal"}});

        return crow::response(r.status_code, r.text); });

    int port = 18080;
    if (const char *p = std::getenv("PORT"))
    {
        port = std::stoi(p);
    }
    app.port(port).multithreaded().run();

    curl_global_cleanup();

}