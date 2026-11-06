from helpers import parsed_email

from phishing_detector.checks import content


def _found(html, text=None):
    return {f.id: f for f in content.check(parsed_email(text=text, html=html), [])}


def test_a_lot_of_hidden_text():
    padding = "harmless words " * 20  # 260 characters of hidden padding
    assert "content.hidden_text" in _found(f'<p>Sign in</p><div style="display:none">{padding}</div>')
    assert "content.hidden_text" in _found(f'<p>Sign in</p><span style="font-size:0px">{padding}</span>')
    # A short preheader (the hidden preview line of newsletters) is normal.
    assert "content.hidden_text" not in _found('<div style="display: none">Our November news, in brief</div><p>Hello</p>')
    assert "content.hidden_text" not in _found(f'<p style="font-size:0.9em">{padding}</p>')  # small, not zero


def test_invisible_characters_inside_words():
    assert "content.zero_width" in _found("<p>Your Example​Bank account</p>")
    assert "content.zero_width" in _found("<p>pass­word</p>")
    # Padding between spaces after a preheader is a common newsletter habit, not a trick.
    assert "content.zero_width" not in _found("<p>News ‌ ‌ ‌ of the week</p>")


def test_an_email_that_is_just_an_image_with_a_link():
    image_link = '<a href="https://portal.example.net/"><img src="cid:banner"></a>'
    assert "content.image_only" in _found(image_link, text=None)
    assert "content.image_only" not in _found(image_link + "<p>" + "Our monthly report is ready to read. " * 3 + "</p>", text=None)
    assert "content.image_only" not in _found(image_link, text="The monthly report is ready, see the link in this message.")
    assert "content.image_only" not in _found("<p><img src='cid:logo'></p>", text=None)  # no link
