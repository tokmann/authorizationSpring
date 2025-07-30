# AuthorizationSpring

Простой проект - практика по авторизации и аутентификации на Spring Boot с использованием JWT.

## 📌 Описание

Данный проект реализует базовую систему регистрации и входа в систему с раздачей JWT-токенов. В проекте предусмотрены:

- Регистрация новых пользователей
- Аутентификация (вход в систему)
- Использование Spring Security и JWT

## 🚀 Технологии

- Java 17
- Spring Boot
- Spring Security
- JWT (JSON Web Token)
- Maven

## 🔧 Запуск проекта

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/tokmann/authorizationSpring.git
   cd authorizationSpring
2. Соберите и запустите приложение:
   ```bash
   ./mvnw spring-boot:run
3. Приложение будет доступно на http://localhost:8080

## 🔑 Эндпоинты
- POST /auth/register — регистрация нового пользователя

- POST /auth/login — вход и получение JWT

- GET /auth/check — доступен для роли USER

## 🛡️ Безопасность

Используется фильтр JWT, который обрабатывает все входящие запросы, валидирует токен и устанавливает контекст безопасности.
