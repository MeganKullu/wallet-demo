package com.example.walletdemo.services;

import com.example.walletdemo.dto.TransactionDTO;
import com.example.walletdemo.dto.TransactionSummaryDTO;
import com.example.walletdemo.models.Transaction;
import com.example.walletdemo.models.TransactionType;
import com.example.walletdemo.models.User;
import com.example.walletdemo.repositories.TransactionRepository;
import com.itextpdf.text.DocumentException;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class TransactionService {

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PdfService pdfService;

    // Get all transactions
    public List<Transaction> getAllTransactions() {
        return transactionRepository.findAll();
    }

    // Get all transactions as DTOs
    public List<TransactionDTO> getAllTransactionsDTO() {
        List<Transaction> transactions = transactionRepository.findAll();
        return transactions.stream()
                .map(TransactionDTO::new)
                .collect(Collectors.toList());
    }

    // Get transactions for a specific user
    public List<Transaction> getTransactionsByUserId(Long userId) {
        return transactionRepository.findBySenderIdOrReceiverId(userId, userId);
    }

    // Get transactions for a specific user as DTOs with correct direction
    public List<TransactionDTO> getTransactionsByUserIdDTO(Long userId) {
        List<Transaction> transactions = transactionRepository.findBySenderIdOrReceiverId(userId, userId);
        List<TransactionDTO> dtos = transactions.stream()
                .map(TransactionDTO::new)
                .collect(Collectors.toList());

        // Set the direction from the user's perspective
        dtos.forEach(dto -> dto.setDirectionForUser(userId));

        return dtos;
    }

    // Calculate transaction summary for admin dashboard
    public TransactionSummaryDTO getTransactionSummary() {
        List<Transaction> transactions = transactionRepository.findAll();
        TransactionSummaryDTO summary = new TransactionSummaryDTO();

        summary.setTransactionCount(transactions.size());

        for (Transaction transaction : transactions) {
            if (transaction.getType() == TransactionType.DEPOSIT) {
                summary.setTotalIn(summary.getTotalIn() + transaction.getAmount());
            } else if (transaction.getType() == TransactionType.WITHDRAWAL) {
                summary.setTotalOut(summary.getTotalOut() + transaction.getAmount());
            } else if (transaction.getType() == TransactionType.TRANSFER) {
                summary.setTotalTransferred(summary.getTotalTransferred() + transaction.getAmount());
            }
        }

        return summary;
    }

    public void emailTransactionSummary(User user) throws DocumentException, MessagingException {
        // Get user transactions direction
        List<TransactionDTO> transactions = getTransactionsByUserIdDTO(user.getId());

        // Generate PDF
        byte[] pdfBytes = pdfService.generateTransactionSummary(user, transactions);

        // Format date for filename
        String date = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE);
        String filename = "transaction_summary_" + date + ".pdf";

        // Create email content
        String subject = "Your Transaction Summary - " + date;
        String body = "<h2>Hello " + user.getName() + ",</h2>" +
                "<p>Please find attached your transaction summary as of " + date + ".</p>" +
                "<p>Your current balance is: $" + user.getWallet().getBalance() + "</p>" +
                "<p>Thank you for using our services!</p>" +
                "<p>Regards,<br>Wallet App Team</p>";

        // Send email directly to the user
        emailService.sendTransactionSummary(user.getEmail(), subject, body, pdfBytes, filename);
    }

}