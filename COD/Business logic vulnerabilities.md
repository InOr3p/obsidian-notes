
Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior.

**Note**: in this context, the term *business logic* simply refers to the set of rules that define how the application operates.

## Examples

- Excessive trust in client-side controls
- Failing to handle unconventional input
- Making flawed assumptions about user behavior
- Domain-specific flaws
- Providing an encryption oracle

### Excessive trust in client-side controls

A fundamentally flawed assumption is that users will only interact with the application via the provided web interface.

###### Lab: Excessive trust in client-side controls

- This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

- Intercept the "add to cart" request of the leather jacket and notice that in the request body there's the price:

```http
productId=1&redir=PRODUCT&quantity=1&price=1337
```

- Just change the price to a smaller quantity and buy the product!

###  Failing to handle unconventional input

One aim of the application logic is to restrict user input to values that adhere to the business rules. For example, the application may be designed to accept arbitrary values of a certain data type, but the logic determines whether or not this value is acceptable from the perspective of the business.

###### Lab: High-level logic vulnerability

- This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

- Intercept the "add to cart" request of the leather jacket and notice that in the request body there's the quantity field:

```http
productId=1&redir=PRODUCT&quantity=1
```

- Just add another product with a negative quantity:

```http
productId=2&redir=PRODUCT&quantity=-16
```

- Now you should have a leather jacket and -16 `productId` 2, hence you should be able to buy the leather jacket!


### Making flawed assumptions about user behavior

One of the most common root causes of logic vulnerabilities is making flawed assumptions about user behavior.

- Trusted users won't always remain trustworthy
- Users won't always supply mandatory input
- Users won't always follow the intended sequence

###### Lab: Inconsistent security controls

- Notice that to be administrator, we must have an account with a *\@dontwannacry.com* email address.
- Register a new account using the email provided.
- Login with the new account.
- Change the email to another one with the suffix *\@dontwannacry.com*.  Now we can access to the admin panel and delete the user carlos!

###### Lab: Insufficient workflow validation

- Login and buy any item that you can afford with your store credit.
- Observe that when you place an order, the `POST /cart/checkout` request redirects you to an order confirmation page `GET /cart/order-confirmation?order-confirmation=true`
- Add the leather jacket to your basket.
- Resend the order confirmation request. Observe that the order is completed without the cost being deducted from your store credit and the lab is solved.

###### Lab: Flawed enforcement of business rules

- Log in and notice that there is a coupon code, `NEWCUST5`.
- At the bottom of the page, sign up to the newsletter. You receive another coupon code, `SIGNUP30`.
- Add the leather jacket to your cart.
- Go to the checkout and apply both of the coupon codes to get a discount on your order.
- Try applying the codes more than once. Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been applied. However, if you alternate between the two codes, you can bypass this control.
- Reuse the two codes enough times to reduce your order total to less than your remaining store credit. Complete the order to solve the lab.


## Prevention

- Developers and testers must understand the domain of the application
- No implicit assumptions about user behavior
- No implicit assumptions about the behavior of other parts of the application