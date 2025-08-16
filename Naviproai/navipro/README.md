# NaviPro.ai Backend

This is the backend service for NaviPro.ai, a personalized learning roadmap generator and career development assistant.

## 🚀 Getting Started

### Prerequisites

- Node.js (v22 or higher recommended)
- npm
- A running instance of the AI agent service.
- A MongoDB database (e.g., from MongoDB Atlas)

### Installation & Setup

1. **Clone the repository:**

    ```sh
    git clone <repository-url>
    cd navipro
    ```

2. **Install dependencies:**

    ```sh
    npm install
    ```

3. **Set up environment variables:**
    Create a `.env` file in the root directory. You can copy the contents from your `.env` file provided in the context. Ensure all variables like `DATABASE_URL`, `JWT_SECRET`, and API keys are correctly filled out.

4. **Run the application:**

    ```sh
    # For development with hot-reloading
    npm run start:dev
    ```

    The application will be running at `http://localhost:3000/api`.

## ✨ Features

### 🗺️ AI Roadmap Generation

Generates a personalized learning roadmap based on user goals and current skill level.

- **Structure:** Months → Weeks → 5 Daily Tasks per week.
- **Task Metadata:** Each task includes `estimated_time`, `resources`, `goal`, `task_id`, `completed`, and `completed_date`.

### 💬 AI Chat Assistant

Provides a context-aware chat assistant powered by a Large Language Model (LLM).

- **Context:** Based on the user’s goal, target role, and completed tasks.
- **Memory:** Maintains the last 20 messages in the chat history.
- **Tone:** Responds with motivational, supportive, and learning-specific content.

### 🔥 Streak System

Keeps users engaged by tracking their consistency.

- **Flexible Types:** Supports both **daily** and **weekly** streaks based on user preference.
- **Tracking:** Monitors current and longest streaks.
- **Integration:** Automatically updates when a user completes a task.

### 🔔 Multi-Channel Notifications

A robust system to keep users informed and motivated.

- **In-App:** Stores notifications for users to view within the application.
- **Email:** Sends email notifications for important events.
- **Push Notifications:** Placeholder for sending push notifications to mobile devices.
- **Delivery Strategy:**
  - **In-App:** All notifications are available in-app for a persistent history.
  - **Push Notifications:** Used for timely, high-priority alerts to encourage immediate action (e.g., `STREAK_REMINDER`, `MOTIVATIONAL_MESSAGE`, `PROGRESS_UPDATE`).
  - **Email:** Used for less time-sensitive updates, summaries, or as a fallback (e.g., weekly `NEW_RECOMMENDATION` digests, monthly `PROGRESS_UPDATE` reports).

### 🎥 Weekly Video Recommendations

Fetches relevant YouTube videos to supplement learning.

- **Criteria:** Based on the current week’s focus and the user's target role.
- **Returns:** A list of video objects containing `title`, `url`, `channel`, `views`, `duration`, and `thumbnail`.
- **Resilience:** Falls back to dummy videos if the YouTube API is unavailable.

## 🔁 API Endpoints

All endpoints are prefixed with `/api`. Endpoints marked with a 🔒 require authentication.

### Health Check

- `GET /health`: Checks the health of the service.

### Authentication (`/auth`)

- `POST /auth/register`: Register a new user with email and password.
- `POST /auth/login`: Log in a user and get a JWT.
- `GET /auth/google`: Redirect to Google for authentication.
- `GET /auth/google/callback`: Callback URL for Google OAuth.

### AI (`/`)

- `POST /generate_roadmap` 🔒: Generates a personalized learning roadmap.
- `POST /chat` 🔒: Interact with the AI chat assistant.

### Users (`/users`) 🔒

- `GET /`: Get a list of all users (admin only).
- `GET /:id`: Get a specific user by their ID.

### Streaks (`/streaks`) 🔒

- `GET /`: Get the current and longest streak for the authenticated user.
- `PATCH /type`: Change the authenticated user's preferred streak type (daily/weekly).

### Notifications (`/notifications`) 🔒

- `GET /`: Get all notifications for the authenticated user.
- `PATCH /:notificationId/read`: Mark a specific notification as read.
- `PATCH /read/all`: Mark all of the user's notifications as read.

### Roadmap & Progress (`/roadmap`) 🔒

- `GET /daily-task`: Get the next uncompleted daily task for the authenticated user.
- `POST /complete-task/:taskId`: Mark a task as complete for the authenticated user.

### Progress (`/user-progress`) 🔒

- `GET /`: Get the authenticated user's overall progress.

### Recommendations (`/week-videos`) 🔒

- `GET /`: Get weekly video recommendations for the authenticated user.
