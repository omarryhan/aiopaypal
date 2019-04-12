<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/3/39/PayPal_logo.svg/527px-PayPal_logo.svg.png" alt="Logo" width="400" height="100"/>
  <p align="center">
    <a href="https://github.com/omarryhan/aiopaypal"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square"></a>
    <a href="https://pepy.tech/badge/aiopaypal"><img alt="Downloads" src="https://pepy.tech/badge/aiopaypal"></a>
    <a href="https://pepy.tech/badge/aiopaypal/month"><img alt="Monthly Downloads" src="https://pepy.tech/badge/aiopaypal/month"></a>
  </p>
</p>

# Aiopaypal

Async Wrapper for Paypal's REST API

## Setup ⚙️

    $ pip install aiopaypal

## Dependencies

- aiohttp
- aiofiles
- pyopenssl

## Usage

### Init

    from aiopaypal import Paypal

    aiopaypal = Paypal(
        mode='live',
        client_id='client_id',
        client_secret='client_secret',
    )

### Create a user subscription

**1. Create a payment experience (Optional) (Do only once)**:

    payment_experience = await aiopaypal.post(
        url='/v1/payment-experience/web-profiles'
        json={
            'name': 'Payment profile name',
            'presentation': {
                'logo_image': 'https://brand-logo.png,
                'brand_name': 'Brand Name'
            },
            'flow_config': {
                'landing_page_type': 'Billing',
                'user_action': 'commit',
                'return_uri_http_method': 'GET'
            },
            'input_fields': {
                'no_shipping': 1,  # No shipping address (digital goods)
            },
            'temporary': False
        }

    )

**2. Create a billing plan (Where you specify the details of your plan) (Do only once)**:

    billing_plan = await aiopaypal.post(
        url='/v1/payments/billing-plans',
        json={
            "name": 'Name of the plan',
            "description": 'Description of the plan',
            "type": "INFINITE",
            "payment_definitions": [
                {
                    "name": 'Name of the payment,
                    "cycles": "0",
                    "frequency": "MONTH",
                    "frequency_interval": "1",
                    "type": "REGULAR",
                    "amount": {
                        "value": str(123),
                        "currency": 'usd'
                    },
                }
            ],
            "merchant_preferences": {
                "setup_fee": {
                    "value": str(123),
                    "currency": currency
                },
                "auto_bill_amount": "yes",  # Default "NO",
                'return_url': 'https://example.com/payment/success-callback',
                'cancel_url': 'https://example.com/payment/cancel-callback,
                "initial_fail_amount_action": "cancel",  # Default CONTINUE
                "max_fail_attempts": "3",
                "auto_bill_amount": "YES",
            }
        }
    )

**3. Create webhooks to listen for subscription events (Do only once)**:

    hook_profile = await aiopaypal.post(
        url='/v1/notifications/webhooks',
        json={
            url='https://example.com/webhook/',
            event_types=[
                {'name': 'BILLING.SUBSCRIPTION.CANCELLED'},
                {'name': 'BILLING.SUBSCRIPTION.SUSPENDED'},
                {'name': 'BILLING.SUBSCRIPTION.RE-ACTIVATED'},
            ]
        }
    )

**4. Create a billing agreement (Where you bind a user to the billing plan created at "2.") and execute it**:

    async def create_agreement():
        return await aiopaypal.post(
            url='',
            json={
                'name': 'Agreement name',
                'description': 'Agreement Description',
                'start_date': (
                    datetime.datetime.utcnow() + \
                    datetime.timedelta(days=1)
                ).isoformat()[:-7] + 'Z'  # The start date must be no less than 24 hours after the current date as the agreement can take up to 24 hours to activate.
                'plan': {
                    'id': billing_plan['id']
                },
                'payer': {
                    'payment_method': 'paypal',
                    'payer_info': {
                        'email': 'email@email.email'
                    }
                }
            }
        )

    def get_execute_from_response(response):
        for link in response['links']:
            if link['rel'] == 'execute':
                return link['href']

**4.1 Create an agreement**:

    @app.route('/create-agreement)
    async def create_agreement():
        billing_agreement = await create_agreement()
        return make_user_open(get_execute_from_response(billing_agreement))

**4.2 Activate on success**:

    # Second step (user callback)
    @app.route('/success-callback', methods=['GET'])
    async def finalize_agreement(request):
        token = request.args.get('token')

        user_id = request['session']['user_id']

        active_agreement = await aiopaypal.post(
            '/v1/payments/billing-agreements/{}/agreement-execute'.format(
                token
            ),
            extra_headers={'Content-Type': 'application/json'}
        )

        if active_agreement['state'].lower() != 'active' and \
            active_agreement['state'].lower() != 'pending':
        else:
            await store_user_agreement_id(user_id, active_agreement['id'])
            activate_premium_product(user_id)

        return_to_user('Payment {}'.format(active_agreement['state']))

**5. Listen to agreement changes**:

    @app.route('/webhook', methods=['POST', 'GET'])
    async def hook(request):
        try:
            await aiopaypal.verify_from_headers(
                webhook_id=webhook['id'],  # webhook response from "3."
                event_body=request.body.decode(),
                headers=headers
            )
        except PaypalError as e:
            logger.exception(e)
            return
        else:
            event = request.json

            event_type = event.get('event_type')

            agreement_id = event['resource']['id']

            if event_type == 'BILLING.SUBSCRIPTION.SUSPENDED':
                logger.info('Billing agreement {} suspended'.format(agreement_id))
                await suspend_agreement_by_agreement_id(
                    agreement_id
                )

            elif event_type == 'BILLING.SUBSCRIPTION.CANCELLED':
                logger.info('Billing agreement {} cancelled'.format(agreement_id))
                await cancel_agreement_by_id(
                    agreement_id
                )

            elif event_type == 'BILLING.SUBSCRIPTION.RE-ACTIVATED':
                logger.info(
                    'Agreement with ID: {} REACTIVATED'.format(
                        agreement_id
                    )
                )
                await reactivate_agreement_by_id(
                    agreement_id
                )

            elif event_type == 'PAYMENT.SALE.PENDING' or \
                event_type == 'PAYMENT.ORDER.CREATED' or \
                event_type == 'BILLING.SUBSCRIPTION.CREATED':
                logger.info('Payment/Subscription Created')

            else:
                logger.critical(
                    'Got unexpected event type {}'.format(event['resource']['id'])
                )

        finally:
            # must return 200, else Paypal won't stop sending
            return response.text('OK')

### Create a user payment

    ... Figured it out? Help others and make a pull request :)

## Contact 📧

Like my work? Have an exciting product and think we can work together?

Let's talk. Send me an email @ omarryhan@gmail.com

## Buy me a coffee ☕

**Bitcoin:** 3NmywNKr1Lzo8gyNXFUnzvboziACpEa31z

**Ethereum:** 0x1E1400C31Cd813685FE0f6D29E0F91c1Da4675aE

**Bitcoin Cash:** qqzn7rsav6hr3zqcp4829s48hvsvjat4zq7j42wkxd

**Litecoin:** MB5M3cE3jE4E8NwGCWoFjLvGqjDqPyyEJp

**Paypal:** https://paypal.me/omarryhan
