# Contribution Guidelines

Thank you for contributing to MEVChargeHook! We welcome community contributions to improve the security, functionality, and usability of this project.

## Reporting Issues

- Clearly describe the issue, including steps to reproduce, expected behavior, and actual behavior.
- Include details like Solidity version, Foundry version, and relevant dependencies.

[Open an Issue](https://github.com/MrLightspeed/MEVChargeHook/issues/new)

## Suggesting Enhancements

- Outline your suggested improvement clearly.
- Explain current limitations and how your proposal resolves them.
- Provide supporting details or examples.

## Submitting Pull Requests

Follow these structured steps:

1. Fork the repository and create a new branch:

   git checkout -b feature/<feature-name>

2. Clearly commit your changes:

   git commit -m "feat: your descriptive commit message"

3. Push your branch:

   git push origin feature/<feature-name>

4. Open a Pull Request clearly against the main branch. Clearly explain your changes and reference any relevant issues.

## Code Standards

- Adhere to the Solidity Style Guide: https://docs.soliditylang.org/en/latest/style-guide.html
- Write secure, clear, modular, and well-documented code.
- Include NatSpec documentation (/// @notice, /// @dev) on public functions.
- Write and pass tests before submission.

Run locally:

   forge clean  
   forge build  
   forge test  

## License

All contributions are licensed under the MIT License.

MIT License  
Copyright (c) 2024 MrLightspeed
