const stripe = require('stripe')('sk_test_V816yh3aCvg1JK0w16EkwiMs00eeWxmLBD')

exports.handler = async function(event) {
  try {
    console.log(event)
    console.log(event.body)
    const { tokenId, email, name, description, amount } = JSON.parse(event.body)

    const customer = await stripe.customers.create({
      description: email,
      source: tokenId,
    })

    const data = await stripe.charges.create({
      customer: customer.id,
      amount,
      name,
      description,
      currency: 'usd',
    })

    return {
      statusCode: 200,
      body: JSON.stringify(data),
    }
  } catch (error) {
    console.log(err)
    return {
      statusCode: 500,
      body: err.message,
    }
  }
}
