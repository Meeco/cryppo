FROM ruby:2.5.7

ENV APP_PATH /app

WORKDIR /tmp/
COPY Gemfile* /tmp/
RUN bundle install

WORKDIR $APP_PATH

