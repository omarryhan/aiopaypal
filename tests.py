'''
Couldn't find valid events + cert to test with
These tests never passed so do not rely on them
'''

from aiopaypal import Paypal, PaypalError
import asyncio
import pytest
import zlib

pytestmark = pytest.mark.asyncio

WEBHOOK_EVENT_ID = 'WH-1S115631EN580315E-9KH94552VF7913711'
EVENT_BODY = '{"id":"WH-0G2756385H040842W-5Y612302CV158622M","create_time":"2015-05-18T15:45:13Z","resource_type":"sale","event_type":"PAYMENT.SALE.COMPLETED","summary":"Payment completed for $ 20.0 USD","resource":{"id":"4EU7004268015634R","create_time":"2015-05-18T15:44:02Z","update_time":"2015-05-18T15:44:21Z","amount":{"total":"20.00","currency":"USD"},"payment_mode":"INSTANT_TRANSFER","state":"completed","protection_eligibility":"ELIGIBLE","protection_eligibility_type":"ITEM_NOT_RECEIVED_ELIGIBLE,UNAUTHORIZED_PAYMENT_ELIGIBLE","parent_payment":"PAY-86C81811X5228590KKVNARQQ","transaction_fee":{"value":"0.88","currency":"USD"},"links":[{"href":"https://api.sandbox.paypal.com/v1/payments/sale/4EU7004268015634R","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/payments/sale/4EU7004268015634R/refund","rel":"refund","method":"POST"},{"href":"https://api.sandbox.paypal.com/v1/payments/payment/PAY-86C81811X5228590KKVNARQQ","rel":"parent_payment","method":"GET"}]},"links":[{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-0G2756385H040842W-5Y612302CV158622M","rel":"self","method":"GET"},{"href":"https://api.sandbox.paypal.com/v1/notifications/webhooks-events/WH-0G2756385H040842W-5Y612302CV158622M/resend","rel":"resend","method":"POST"}]}'
TRANSMISSION_ID = "dfb3be50-fd74-11e4-8bf3-77339302725b"
TIMESTAMP= "2015-05-18T15:45:13Z"
WEBHOOK_ID = "4JH86294D6297924G"
ACTUAL_SIG = "thy4/U002quzxFavHPwbfJGcc46E8rc5jzgyeafWm5mICTBdY/8rl7WJpn8JA0GKA+oDTPsSruqusw+XXg5RLAP7ip53Euh9Xu3UbUhQFX7UgwzE2FeYoY6lyRMiiiQLzy9BvHfIzNIVhPad4KnC339dr6y2l+mN8ALgI4GCdIh3/SoJO5wE64Bh/ueWtt8EVuvsvXfda2Le5a2TrOI9vLEzsm9GS79hAR/5oLexNz8UiZr045Mr5ObroH4w4oNfmkTaDk9Rj0G19uvISs5QzgmBpauKr7Nw++JI0pr/v5mFctQkoWJSGfBGzPRXawrvIIVHQ9Wer48GR2g9ZiApWg=="
CERT_URL = 'https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-a5cafa77'  # Return 400
EXPECTED_SIG = TRANSMISSION_ID + "|" + TIMESTAMP + "|" + \
    WEBHOOK_ID + "|" + \
    str(zlib.crc32(EVENT_BODY.encode('utf-8')) & 0xffffffff)

@pytest.fixture
def paypal():
    return Paypal()

async def test_verify_with_headers(paypal):
    headers = {
        'paypal-transmission-id': TRANSMISSION_ID,
        'paypal-transmission-time': TIMESTAMP,
        'paypal-transmission-sig': ACTUAL_SIG,
        'paypal-cert-url': CERT_URL,
        'paypal-auth-algo': 'SHA256withRSA',
    }
    verified = await paypal.verify_from_headers(
        event_body=EVENT_BODY,
        headers=headers,
        webhook_id=WEBHOOK_ID
    )
    assert verified

async def test_verify_cert_chain(paypal):
    cert = await paypal._get_cert(CERT_URL)
    assert cert

    verified = await paypal._verify_certificate_chain(cert)
    assert verified is True


