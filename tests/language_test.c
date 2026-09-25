#include "ankah/language.h"
#include "language_internal.h"
#include "language_names.h"
#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *name) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        ++failures;
    }
}

static ankah_language select_value(const char *value) {
    ankah_request request;
    memset(&request, 0, sizeof(request));
    request.count = 1;
    ankah_header_set_name(&request.headers[0], "Accept-Language", 15);
    strcpy(request.headers[0].value, value);
    return ankah_language_select(&request);
}

static const char *test_text(ankah_language language, const char *name) {
    if (strcmp(name, "escape") == 0) return "&<>\"'";
    return ankah_language_text(language, name);
}

static int render(const char *source, unsigned char *output, size_t capacity,
                  size_t *written) {
    return ankah_language_render_html(ANKAH_LANGUAGE_EN,
        (const unsigned char *)source, strlen(source), output, capacity, written,
        test_text);
}

int main(void) {
    const struct ankah_language_keyword *keyword;
    static const char source[] =
        "<title><!--#echo var=\"title\" --></title>"
        "<p><!--#echo var=\"throughput_note\" --></p>"
        "<!-- ordinary --><!--#echo var=\"escape\" -->";
    static const char *invalid[] = {
        "<!--#echo var=\"unknown\" -->",
        "<!--#echo var=\"title\"",
        "<!--#echo var=\"title\">",
        "<!--#echo var=\"\" -->",
        "<!--#echo var='title' -->",
        "<!--#echo  var=\"title\" -->",
        "<!--#ECHO var=\"title\" -->",
        "<!--#echo var=\"title\" encoding=\"none\" -->",
        "<!--#include file=\"index.html\" -->",
        "<!--#exec cmd=\"date\" -->",
        "<!--#printenv -->",
        "<!--#"
    };
    unsigned char rendered[512];
    size_t rendered_size = 0, exact_size = 0, i;
    keyword = ankah_language_lookup("en", 2);
    check(keyword && keyword->language == ANKAH_LANGUAGE_EN, "exact lookup");
    keyword = ankah_language_lookup("JA", 2);
    check(keyword && keyword->language == ANKAH_LANGUAGE_JA, "Japanese lookup");
    keyword = ankah_language_lookup("es", 2);
    check(keyword && keyword->language == ANKAH_LANGUAGE_ES, "Spanish lookup");
    check(ankah_language_lookup("EN", 2) != NULL, "case-insensitive lookup");
    check(ankah_language_lookup("en-AU", 5) == NULL, "exact registry boundary");
    check(ankah_language_lookup("english", 2) != NULL, "bounded lookup");
    check(ankah_language_lookup("english", 7) == NULL, "near miss");
    check(select_value("fr, en;q=0.5") == ANKAH_LANGUAGE_EN, "weighted selection");
    check(select_value("ja-JP, es-MX;q=0.5") == ANKAH_LANGUAGE_JA,
          "Japanese regional fallback");
    check(select_value("ja;q=0.3, es-AR;q=0.8") == ANKAH_LANGUAGE_ES,
          "Spanish quality selection");
    check(strcmp(ankah_language_tag(ANKAH_LANGUAGE_JA), "ja") == 0 &&
          strcmp(ankah_language_tag(ANKAH_LANGUAGE_ES), "es") == 0,
          "selected language tags");
    check(strcmp(ankah_language_text(ANKAH_LANGUAGE_JA, "starting"), "開始しています") == 0 &&
          strcmp(ankah_language_text(ANKAH_LANGUAGE_ES, "starting"), "Iniciando") == 0,
          "dashboard catalog translations");
    check(strcmp(ankah_language_message(ANKAH_LANGUAGE_ES, "Invalid challenge\n"),
                 "El desafío no es válido\n") == 0, "response translation");
    check(select_value("EN-au") == ANKAH_LANGUAGE_EN, "progressive fallback");
    check(select_value("*;q=0.2") == ANKAH_LANGUAGE_EN, "wildcard");
    check(select_value("en;q=0") == ANKAH_LANGUAGE_EN, "English final default");
    check(select_value("fr;q=bogus, en;q=0.2") == ANKAH_LANGUAGE_EN,
          "malformed item ignored");
    check(render(source, rendered, sizeof(rendered) - 1, &rendered_size) == 0,
          "dashboard SSI renders");
    rendered[rendered_size] = 0;
    check(strstr((char *)rendered, "<title>Ankah dashboard</title>") != NULL,
          "dashboard title localized");
    check(strstr((char *)rendered, "itself: challenge") != NULL,
          "dashboard text localized");
    check(strstr((char *)rendered, "<!-- ordinary -->&amp;&lt;&gt;&quot;&#39;") != NULL,
          "dashboard text HTML escaped");
    check(render(source, NULL, sizeof(rendered), &exact_size) == 0,
          "dashboard SSI size calculated");
    check(render(source, rendered, exact_size, &rendered_size) == 0 &&
          rendered_size == exact_size, "dashboard SSI exact buffer");
    check(exact_size > 0 && render(source, rendered, exact_size - 1,
                                  &rendered_size) != 0,
          "dashboard SSI is bounded");
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        check(render(invalid[i], rendered, sizeof(rendered), &rendered_size) != 0,
              "invalid dashboard SSI rejected");
    return failures ? 1 : 0;
}
