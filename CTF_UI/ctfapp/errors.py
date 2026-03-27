from flask import render_template
from werkzeug.exceptions import HTTPException


def register_error_handlers(app) -> None:
    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):
        return render_template(
            "error.html",
            status_code=error.code,
            error_message=error.description,
        ), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error: Exception):
        app.logger.exception("Unhandled exception")
        return render_template(
            "error.html",
            status_code=500,
            error_message="An unexpected error occurred.",
        ), 500