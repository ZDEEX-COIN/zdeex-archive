
# Hush Core (hushd) Software Contribution Guidelines

Thank you for reaching out and trying to make Hush an even better software application and cryptocoin platform. These contribution guidelines shall help you figuring out where you can be helpful and how to easily get started.

## Table of Contents

0. [Types of contributions we're looking for](#types-of-contributions-were-looking-for)
0. [Ground rules & expectations](#ground-rules--expectations)
0. [How to contribute](#how-to-contribute)
0. [Style guide](#style-guide)
0. [Setting up your environment](#setting-up-your-environment)
0. [Contribution review process](#contribution-review-process)
0. [Community](#community)

## Types of contributions we're looking for
There are many ways you can directly contribute to Hush:

* Debug and test the Hush Core code
* Find and fix bugs
* Improve suboptimal code
* Extend our software
* Perform a secure code review of Hush Full Node and other Hush-related software

We have a curated list of projects with details about difficulty level and languages involved: https://git.hush.is/hush/projects

Interested in making a contribution? Read on!

## Ground rules & expectations

Before we get started, here are a few things we expect from you (and that you should expect from others):

* Be kind and thoughtful in your conversations around this project. We all come from different backgrounds and projects, which means we likely have different perspectives on "how free software and open source is done." Try to listen to others rather than convince them that your way is correct.
* Open Source Guides are released with a [Contributor Code of Conduct](./code_of_conduct.md). By participating in this project, you agree to abide by its terms.
* If you open a pull request, please ensure that your contribution does not increase test failures. If there are additional test failures, you will need to address them before we can merge your contribution.
* When adding content, please consider if it is widely valuable. Please don't add references or links to things you or your employer have created as others will do so if they appreciate it.

## How to contribute

If you'd like to contribute, start by searching through the [issues](https://git.hush.is/hush/hush3/issues) and [pull requests](https://git.hush.is/hush/hush3/pulls) to see whether someone else has raised a similar idea or question.

If you don't see your idea listed, and you think it can contribute to Hush, do one of the following:
* **If your contribution is minor,** such as a fixing a typo, open a pull request.
* **If your contribution is major,** such as a new feature or bugfix, start by opening an issue first. That way, other contributors can weigh in on the discussion before you do any work.

## Style guide

Don't write shitty code. Do not emulate "jl777 code style" from Komodo, we consider that a bug, not a feature.

## Setting up your environment

The Hush Core (hushd) is mainly written in C++ with specific modules written in C. Follow the [Install](https://git.hush.is/hush/hush3/src/branch/master/INSTALL.md) instructions to build hushd from sources. For more informations about the Hush Platform and a full API documentation please visit the official [Hush Developer documentation](https://faq.hush.is/rpc/)

Other Hush software is written in Rust or Go. We avoid Javascript at all costs.

## Contribution review process

We will tell you if we like your stuff.
