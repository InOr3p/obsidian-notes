
- Web cache deception is a vulnerability that enables an attacker to trick a web cache into storing sensitive, dynamic content. It's caused by discrepancies between how the cache server and origin server handle requests.

In a web cache deception attack, an attacker persuades a victim to visit a malicious URL, inducing the victim's browser to make an ambiguous request for sensitive content. The cache misinterprets this as a request for a static resource and stores the response. The attacker can then request the same URL to access the cached response, gaining unauthorized access to private information.


## Web caches

A web cache is a system that sits between the origin server and the user. When a client requests a static resource, the request is first directed to the cache. If the cache doesn't contain a copy of the resource (known as a **cache miss**), the request is forwarded to the origin server, which processes and responds to the request. The response is then sent to the cache before being sent to the user. The cache uses a preconfigured set of rules to determine whether to store the response.

When a request for the same static resource is made in the future, the cache serves the stored copy of the response directly to the user (known as a **cache hit**).


![[Schermata del 2024-12-07 09-40-11.png]]

### Cache keys

When the cache receives an HTTP request, it must decide whether there is a cached response that it can serve directly, or whether it has to forward the request to the origin server. The cache makes this decision by generating a 'cache key' from elements of the HTTP request. Typically, this includes the URL path and query parameters, but it can also include a variety of other elements like headers and content type.

If the incoming request's cache key matches that of a previous request, the cache considers them to be equivalent and serves a copy of the cached response.

### Cache rules

Cache rules determine what can be cached and for how long. Cache rules are often set up to store static resources, which generally don't change frequently and are reused across multiple pages. Dynamic content is not cached as it's more likely to contain sensitive information, ensuring users get the latest data directly from the server.

There are different types of rules:

- static file extension rules: these rules match the file extension of the requested resource, for example `.css` for stylesheets or `.js` for JavaScript files
- static directory rules: these rules match all URL paths that start with a specific prefix. These are often used to target specific directories that contain only static resources, for example `/static` or `/assets`
- file name rules: these rules match specific file names to target files that are universally required for web operations and change rarely, such as `robots.txt` and `favicon.ico`.

Caches may also implement custom rules based on other criteria, such as URL parameters or dynamic analysis.

## Constructing a web cache deception attack

Constructing a basic web cache deception attack involves the following steps:

1. Identify a target endpoint that returns a dynamic response containing sensitive information. Review responses and focus on endpoints that support the `GET`, `HEAD`, or `OPTIONS` methods as requests that alter the origin server's state (like `POST`) are generally not cached.
2. Identify a discrepancy in how the cache and origin server parse the URL path. This could be a discrepancy in how they:
    - map URLs to resources
    - process delimiter characters
    - normalize paths.
3. Craft a malicious URL that uses the discrepancy to trick the cache into storing a dynamic response. When the victim accesses the URL, their response is stored in the cache. You can then send a request to the same URL to fetch the cached response containing the victim's data. Avoid doing this directly in the browser as some applications redirect users without a session or invalidate local data, which could hide a vulnerability.

### Using a cache buster

While testing for discrepancies and crafting a web cache deception exploit, make sure that each request you send has a different **cache key**. Otherwise, you may be served cached responses, which will impact your test results.

As both URL path and any query parameters are typically included in the cache key, you can change the key by adding a query string to the path and changing it each time you send a request. The operation of forcing the store of a URL in the cache server by adding a unique string is also called **cache busting**.


### Detecting cached responses

During testing, to identify cached responses, look at response headers and response times.
Various response headers may indicate that the response is cached. For example:

- The `X-Cache` header provides information about whether a response was served from the cache. Typical values include:
    - `X-Cache: hit`: the response was served from the cache.
    - `X-Cache: miss`: the cache did not contain a response for the request's key, so it was fetched from the origin server. In most cases, the response is then cached. To confirm this, send the request again to see whether the value updates to hit.
    - `X-Cache: dynamic`: the origin server dynamically generated the content. Generally this means the response is not suitable for caching.
    - `X-Cache: refresh`: the cached content was outdated and needed to be refreshed or revalidated.
- The `Cache-Control` header may include a directive that indicates caching, like `public` with a `max-age` higher than `0`. Note that this only suggests that the resource is cacheable. It isn't always indicative of caching, as the cache may sometimes override this header.

If you notice a big difference in response time for the same request, this may also indicate that the faster response is served from the cache.


## Vulnerabilities and Labs

## Exploiting static extension cache rules

If there are discrepancies in how the cache and origin server map the URL path to resources or use delimiters, an attacker may be able to craft a request for a dynamic resource with a static extension that is ignored by the origin server but viewed by the cache.

#### Path mapping discrepancies

*URL path mapping* is the process of associating URL paths with resources on a server, such as files, scripts, or command executions. There are a range of different mapping styles used by different frameworks and technologies. Two common styles are traditional URL mapping and RESTful URL mapping.

Traditional URL mapping represents a direct path to a resource located on the file system. Here's a typical example:

`http://example.com/path/in/filesystem/resource.html`

- `http://example.com` points to the server.
- `/path/in/filesystem/` represents the directory path in the server's file system.
- `resource.html` is the specific file being accessed.

In contrast, REST-style URLs don't directly match the physical file structure. They abstract file paths into logical parts of the API:

`http://example.com/path/resource/param1/param2`

- `http://example.com` points to the server.
- `/path/resource/` is an endpoint representing a resource.
- `param1` and `param2` are path parameters used by the server to process the request.

Discrepancies in how the cache and origin server map the URL path to resources can result in web cache deception vulnerabilities. Consider the following example:

`http://example.com/user/123/profile/wcd.css`

- An origin server using REST-style URL mapping may interpret this as a request for the `/user/123/profile` endpoint and returns the profile information for user `123`, ignoring `wcd.css` as a non-significant parameter.
- A cache that uses traditional URL mapping may view this as a request for a file named `wcd.css` located in the `/profile` directory under `/user/123`. It interprets the URL path as `/user/123/profile/wcd.css`. If the cache is configured to store responses for requests where the path ends in `.css`, it would cache and serve the profile information as if it were a CSS file.

#### Exploiting path mapping discrepancies

To test how the origin server maps the URL path to resources, add an arbitrary path segment to the URL of your target endpoint. If the response still contains the same sensitive data as the base response, it indicates that the origin server ignored the added segment. For example, if modifying `/api/orders/123` to `/api/orders/123/foo` still returns order information.

To test how the cache maps the URL path to resources, you'll need to modify the path to attempt to match a cache rule by adding a static extension. For example, update `/api/orders/123/foo` to `/api/orders/123/foo.js`. If the response is cached, this indicates:

- that the cache interprets the full URL path with the static extension
- that there is a cache rule to store responses for requests ending in `.js`.

Caches may have rules based on specific static extensions. Try a range of extensions, including `.css`, `.ico`, and `.exe`.

###### Lab: Exploiting path mapping for web cache deception
```html
<script>
document.location="https://0ac100dd043d51d281c243bc00620082.web-security-academy.net/my-account/bar.js"
</script>
```

It doesn't work with `FetchAPI` (which is a JavaScript interface for making HTTP requests) because it uses a different caching mechanism than traditional HTTP requests unless we include the credentials (with the `include` header).

#### Delimiter discrepancies

Delimiters specify boundaries between different elements in URLs. The use of characters and strings as delimiters is generally standardized. However, variations still occur between different frameworks or technologies.

Discrepancies in how the cache and origin server use characters and strings as delimiters can result in web cache deception vulnerabilities. Consider the example `/profile;foo.css`:

- The Java Spring framework uses the `;` character to add parameters known as matrix variables. An origin server that uses Java Spring would therefore interpret `;` as a delimiter. It truncates the path after `/profile` and returns profile information.
- Most other frameworks don't use `;` as a delimiter. Therefore, a cache that doesn't use Java Spring is likely to interpret `;` and everything after it as part of the path. If the cache has a rule to store responses for requests ending in `.css`, it might cache and serve the profile information as if it were a CSS file.

An origin server running the Ruby on Rails framework can use `.` as a delimiter to specify the response format:

- `/profile` - This request is processed by the default HTML formatter, which returns the user profile information.
- `/profile.css` - This request is recognized as a CSS extension. There isn't a CSS formatter, so the request isn't accepted and an error is returned.
- `/profile.ico` - This request uses the `.ico` extension, which isn't recognized by Ruby on Rails. The default HTML formatter handles the request and returns the user profile information. In this situation, if the cache is configured to store responses for requests ending in `.ico`, it would cache and serve the profile information as if it were a static file.

Encoded characters may also sometimes be used as delimiters. For example, consider the request `/profile%00foo.js`:

- The OpenLiteSpeed server uses the encoded null `%00` character as a delimiter. An origin server that uses OpenLiteSpeed would therefore interpret the path as `/profile`

#### Exploiting delimiter discrepancies

To use a delimiter discrepancy, you'll need to identify a character that is used as a delimiter by the origin server but not the cache.

Firstly, find characters that are used as delimiters by the origin server. Start this process by adding an arbitrary string to the URL of your target endpoint. For example, modify `/settings/users/list` to `/settings/users/listaaa`.

**Note**: if the response is identical to the original response, this indicates that the request is being redirected. You'll need to choose a different endpoint to test.

Next, add a possible delimiter character between the original path and the arbitrary string, for example `/settings/users/list;aaa`:

- If the response is identical to the base response, this indicates that the `;` character is used as a delimiter and the origin server interprets the path as `/settings/users/list`.
- If it matches the response to the path with the arbitrary string, this indicates that the `;` character isn't used as a delimiter and the origin server interprets the path as `/settings/users/list;aaa`.

Once you've identified delimiters that are used by the origin server, test whether they're also used by the cache. To do this, add a static extension to the end of the path (try for example `/settings/users/list;lab.js`). If the response is cached, this indicates:

- That the cache doesn't use the delimiter and interprets the full URL path with the static extension.
- That there is a cache rule to store responses for requests ending in `.js`.

Make sure to test all ASCII characters and a range of common extensions, including `.css`, `.ico`, and `.exe`.

###### Lab: Exploiting path delimiters for web cache deception

```html
<script>
document.location="https://0a240078036bb4cf811abb09004400a7.web-security-academy.net/my-account;wcd.js"
</script>
```

We can fuzz the request to find a delimiter for the origin server.

#### Delimiter decoding discrepancies

Websites sometimes need to send encoded data in the URL (like for delimiters). However, some parsers decode certain characters before processing the URL. If a delimiter character is decoded, it may then be treated as a delimiter, truncating the URL path.

## Exploiting static directory cache rules

It's common practice for web servers to store static resources in specific directories. Cache rules often target these directories by matching specific URL path prefixes, like `/resources`, `/static`, `/assets`, `/scripts`, or `/images`. These rules can also be vulnerable to web cache deception.

#### Normalization discrepancies

**Normalization** involves converting various representations of URL paths into a standardized format. This sometimes includes decoding encoded characters and resolving dot-segments.

Discrepancies in how the cache and origin server normalize the URL can enable an attacker to construct a **path traversal payload** that is interpreted differently by each parser. Consider the example `/static/..%2fprofile`: an exploitable normalization discrepancy requires that **either the cache or origin server** decodes characters in the path traversal sequence as well as resolving dot-segments.
Hence, to have a normalization discrepancy, we must be in one of these 2 cases:

- the web server  normalizes the URL (and resolves the dot-segment), while the cache server doesn't normalize the URL and has a cache rule for  `/static` folder (caching the URL `/static/..%2fprofile`);
- the web server  doesn't normalize the URL, but the cache server does normalize it and has a cache rule for  `/static` folder, (it then resolves the URL `/static/..%2fprofile` into `/profile` and pass it to the web server).

#### Detecting normalization by the origin server

To test how the origin server normalizes the URL path, send a request to a non-cacheable resource with a path traversal sequence and an arbitrary directory at the start of the path. To choose a non-cacheable resource, look for a method like `POST`. For example, modify `/profile` to `/aaa/..%2fprofile`:

- If the response matches the base response and returns the profile information, this indicates that the path has been interpreted as `/profile`. The origin server decodes the slash and resolves the dot-segment. Hence, the origin server applies normalization.
- If the response doesn't match the base response, for example returning a `404` error message, this indicates that the path has been interpreted as `/aaa/..%2fprofile`. The origin server either doesn't decode the slash or resolve the dot-segment.

#### Detecting normalization by the cache server

You can choose a request with a cached response and resend the request with a path traversal sequence and an arbitrary directory at the start of the static path. For example, `/aaa/..%2fassets/js/stockCheck.js`:

- If the response is no longer cached, this indicates that the cache isn't normalizing the path before mapping it to the endpoint.
- If the response is still cached, this may indicate that the cache has normalized the path to `/assets/js/stockCheck.js`.

#### Exploiting normalization by the origin server

If the origin server resolves encoded dot-segments, but the cache doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure:

`/<static-directory-prefix>/..%2f<dynamic-path>`

For example, consider the payload `/assets/..%2fprofile`:

- The cache interprets the path as: `/assets/..%2fprofile`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache.


#### Exploiting normalization by the cache server

If the cache server resolves encoded dot-segments but the origin server doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure:

`/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>`

**Note**: when exploiting normalization by the cache server, encode all characters in the path traversal sequence.

In this situation, path traversal alone isn't sufficient for an exploit. You'll need to also identify a delimiter that is used by the origin server but not the cache. Test possible delimiters by adding them to the payload after the dynamic path:

- If the origin server uses a delimiter, it will truncate the URL path and return the dynamic information.
- If the cache doesn't use the delimiter, it will resolve the path and cache the response.

For example, consider the payload `/profile;%2f%2e%2e%2fstatic`. The origin server uses `;` as a delimiter:

- The cache interprets the path as: `/profile;/../static` normalizing it and resolving the dot-segments in `/static`
- The origin server interprets the path as: `/profile` (since the `;` delimiter will truncate all the next characters)

###### Lab: Exploiting cache server normalization for web cache deception
```html
<script>
document.location="https://0a240078036bb4cf811abb09004400a7.web-security-academy.net/my-account%23%2f%2e%2e%2fresources/foo.css";
</script>
```


## Exploiting file name cache rules

Certain files such as `robots.txt`, `index.html`, and `favicon.ico` are common files found on web servers. They're often cached due to their infrequent changes. Cache rules target these files by matching the exact file name string.

To identify whether there is a file name cache rule, send a `GET` request for a possible file and see if the response is cached.

Then, check normalization discrepancies for both origin and cache servers (as seen before).

## Prevention

- Always use `Cache-Control` headers to mark dynamic resources, set with the directives `no-store` and `private`.
- Configure your CDN settings so that your caching rules don't override the `Cache-Control` header.
- Activate any protection that your CDN has against web cache deception attacks. Many CDNs enable you to set a cache rule that verifies that the response `Content-Type` matches the request's URL file extension. For example, Cloudflare's Cache Deception Armor.
- Verify that there aren't any discrepancies between how the origin server and the cache interpret URL paths.

## Web cache deception vs Web cache poisoning

- Both exploit caching mechanisms, but they do so in different ways
- **Web cache poisoning** manipulates cache keys to inject malicious content into a cached response, which is then served to other users
- Web cache deception exploits cache rules to trick the cache into storing sensitive or private content, which the attacker can then access