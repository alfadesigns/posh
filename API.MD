# Poshmark iOS API Documentation (v9.28)

This document outlines the structure, authentication mechanism, and key endpoints of the internal Poshmark iOS API, as discovered through reverse engineering of the v9.28 iOS application.

-----

## 1\. General Information

### 1.1. Base URLs

The Poshmark ecosystem uses two primary domains for its operations:

  * **Main API**: `https://api.poshmark.com/api`
  * **Tracking & Analytics**: `https://et.poshmark.com`

### 1.2. Common Headers

All authenticated requests to the main API share a common set of headers to identify the client and session.

```
User-Agent: Poshmark/9.28 (iPhone13,2; iOS 16.4; Scale/3.00) Alamofire/5.10.2
Accept-Language: en-US;q=1.0, ar-US;q=0.9
Accept-Encoding: br;q=1.0, gzip;q=0.9, deflate;q=0.8
X-HTTP_AUTHORIZATION: oauth {access_token}
```

### 1.3. Common URL Parameters

A consistent set of URL parameters are appended to most requests to provide context.

| Parameter | Example | Description |
| :--- | :--- | :--- |
| `api_version` | `0.2` | The version of the API being targeted. |
| `app_version` | `9.28` | The version of the client application. |
| `app_type` | `iphone` | The client platform. |
| `domain` | `us` | The regional domain for the request. |
| `visitor_id` | `6895316...` | A unique identifier for the app installation. |
| `device_id` | `ios2:bf26...` | A unique identifier for the device. |
| `auth_session_id` | `689548b...` | The session ID obtained during login. |

-----

## 2\. Authentication

The API uses a sophisticated **OAuth-based challenge-response mechanism** to secure user login, incorporating Apple's App Attest service to prevent automation.

### 2.1. `POST /devices/{device_id}/challenges`

This is the first step in the login flow. It requests a unique, single-use challenge from the server that must be signed by the device.

  * **Description**: Initiates the login sequence.
  * **Body**: `application/x-www-form-urlencoded`
      * `challenge_for`: `app_attest_assertion`
      * `device_id`: The device's unique identifier.
  * **Successful Response (200 OK)**:
    ```json
    {
      "data": "cad8e535bcd5d725136fa8891a2ac999"
    }
    ```

### 2.2. `POST /auth/users/access_token`

This is the second and final step of the login process. The client sends the signed challenge along with credentials to receive a session token.

  * **Description**: Exchanges user credentials and a signed challenge for an `access_token`.
  * **Body**: `application/x-www-form-urlencoded` containing numerous parameters, most critically:
      * `user_handle`: The user's username.
      * `password`: The user's password.
      * `device_integrity_hash`: A JSON object containing the App Attest assertion (the signed challenge).
      * `iobb`: A large, obfuscated data blob containing a device fingerprint.
  * **Successful Response (200 OK)**:
    ```json
    {
      "access_token": "Njg5NTMxODgzO...Vo0MWdsQQ",
      "auth_session_id": "689548b559f4d6024161ea0e",
      "user": { ... }
    }
    ```

-----

## 3\. Search & Product Endpoints

These endpoints are used for discovering and retrieving product information.

### 3.1. `GET /posts`

The primary endpoint for searching product listings. This is the main endpoint used by the competitive intelligence scripts (`posh.py`, `posh-gui.py`).

  * **Description**: Searches for products based on a query and filters.
  * **Key Parameters**:
      * `request`: A URL-encoded JSON string containing the search query and filters.
          * **Example `request` value**: `{"filters":{"inventory_status":["available"]},"query":"designer jeans"}`
      * `summarize`: `true`
  * **Sample Response Snippet**:
    ```json
    {
      "data": [
        {
          "id": "6856443fe0f2ceb42b57a3ab",
          "title": "Christian Louboutin Bip Bip High Top Sneakers Shoes",
          "brand": "Christian Louboutin",
          "price_amount": { "val": "400.0", ... },
          "aggregates": { "likes": 4, ... },
          ...
        }
      ],
      "more": "...",
      "raw_total": 10000
    }
    ```

### 3.2. `GET /searches/suggested`

Provides type-ahead search suggestions for users as they type. This is used by `posh.py` to mimic user behavior.

  * **Description**: Fetches search suggestions for a given query.
  * **Key Parameters**:
      * `query`: The search term entered by the user.
      * `count`: The maximum number of suggestions to return.
  * **Sample Response Snippet**:
    ```json
    {
        "data": [
            { "type": "query", "kw": "nike shoes" },
            { "type": "brand", "id": "...", "brand": "Nike", "kw": "Nike" }
        ]
    }
    ```

-----

## 4\. User & Account Endpoints

These endpoints are used to manage and retrieve user-specific data.

### 4.1. `GET /users/{user_id}/state/summary`

Fetches a comprehensive summary of the logged-in user's state, including settings, notifications, and profile information.

  * **Description**: Retrieves a snapshot of the user's account data.
  * **Key Parameters**:
      * `user_info`: `true`
      * `notifications`: `true`
      * `feature_settings`: `true`
  * **Sample Response Snippet**:
    ```json
    {
        "user_info": {
            "id": "689531883972a87025962ead",
            "username": "gettrendly",
            ...
        },
        "notifications": { ... },
        "feature_settings": { ... }
    }
    ```

### 4.2. `GET /users/{user_id}/feed/personalized_v2`

Retrieves the user's main "For You" feed content.

  * **Description**: Fetches the personalized product feed for the user.
  * **Key Parameters**:
      * `count`: The number of feed items to return.
      * `summarize`: `true`
  * **Sample Response Snippet**:
    ```json
    {
        "data": [
            {
                "content": {
                    "data": [ { "id": "...", "title": "...", ... } ]
                },
                ...
            }
        ]
    }
    ```

-----

## 5\. Analytics & Tracking

Poshmark uses a separate domain for event tracking and analytics.

### 5.1. `POST https://et.poshmark.com/trck/events`

This is the primary endpoint for logging user interactions and analytics events within the app.

  * **Description**: Sends a batch of analytics events to the tracking server.
  * **Body**: `application/x-www-form-urlencoded`
      * `data`: A URL-encoded JSON string containing an array of event objects. Each object details a user action (e.g., `view_listing`, `search`, `login`).
  * **Response**: Typically a `200 OK` with an empty body.