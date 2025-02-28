package com.example.walletdemo.services;

import com.example.walletdemo.dto.TransactionDTO;
import com.example.walletdemo.models.User;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class PdfService {

    public byte[] generateTransactionSummary(User user, List<TransactionDTO> transactions) throws DocumentException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4);
        PdfWriter.getInstance(document, baos);

        document.open();
        addDocumentMetadata(document, user);
        addTitle(document, user);
        addUserDetails(document, user);
        addTransactionsTable(document, transactions);
        document.close();

        return baos.toByteArray();
    }

    private void addDocumentMetadata(Document document, User user) {
        document.addTitle("Transaction Summary for " + user.getName());
        document.addSubject("Transaction Summary");
        document.addKeywords("Wallet, Transactions, Summary");
        document.addAuthor("Wallet App");
        document.addCreator("Wallet App");
    }

    private void addTitle(Document document, User user) throws DocumentException {
        Font titleFont = new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD, BaseColor.DARK_GRAY);
        Paragraph title = new Paragraph("Transaction Summary", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        document.add(title);
        document.add(Chunk.NEWLINE);
    }

    private void addUserDetails(Document document, User user) throws DocumentException {
        Font regularFont = new Font(Font.FontFamily.HELVETICA, 12, Font.NORMAL);
        Font boldFont = new Font(Font.FontFamily.HELVETICA, 12, Font.BOLD);

        document.add(new Paragraph("User Information", boldFont));
        document.add(new Paragraph("Name: " + user.getName(), regularFont));
        document.add(new Paragraph("Email: " + user.getEmail(), regularFont));
        document.add(new Paragraph("Balance: $" + user.getWallet().getBalance(), regularFont));
        document.add(new Paragraph("Generated on: " + LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE), regularFont));
        document.add(Chunk.NEWLINE);
    }

    private void addTransactionsTable(Document document, List<TransactionDTO> transactions) throws DocumentException {
        Font headerFont = new Font(Font.FontFamily.HELVETICA, 12, Font.BOLD, BaseColor.WHITE);
        Font cellFont = new Font(Font.FontFamily.HELVETICA, 10, Font.NORMAL);

        document.add(new Paragraph("Transaction History", new Font(Font.FontFamily.HELVETICA, 14, Font.BOLD)));
        document.add(Chunk.NEWLINE);

        PdfPTable table = new PdfPTable(6); // 6 columns
        table.setWidthPercentage(100);

        // Set column widths
        float[] columnWidths = {0.7f, 1.3f, 1.3f, 1.0f, 1.5f, 1.2f};
        table.setWidths(columnWidths);

        // Add table headers
        addTableHeader(table, headerFont);

        // Add transaction rows
        for (TransactionDTO transaction : transactions) {
            addTransactionRow(table, transaction, cellFont);
        }

        document.add(table);
    }

    private void addTableHeader(PdfPTable table, Font headerFont) {
        PdfPCell cell;
        BaseColor headerColor = new BaseColor(66, 139, 202);

        String[] headers = {"Type", "Amount", "Direction", "Date", "Description", "Status"};

        for (String header : headers) {
            cell = new PdfPCell(new Phrase(header, headerFont));
            cell.setBackgroundColor(headerColor);
            cell.setPadding(5);
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            table.addCell(cell);
        }
    }

    private void addTransactionRow(PdfPTable table, TransactionDTO transaction, Font cellFont) {
        BaseColor creditColor = new BaseColor(223, 240, 216);
        BaseColor debitColor = new BaseColor(242, 222, 222);
        BaseColor transferColor = new BaseColor(217, 237, 247);

        BaseColor rowColor;
        if (transaction.getDirection().equals("CREDIT")) {
            rowColor = creditColor;
        } else if (transaction.getDirection().equals("DEBIT")) {
            rowColor = debitColor;
        } else {
            rowColor = transferColor;
        }

        addCell(table, transaction.getType(), cellFont, rowColor);
        addCell(table, "$" + transaction.getAmount(), cellFont, rowColor);
        addCell(table, transaction.getDirection(), cellFont, rowColor);

        // Format timestamp (assuming timestamp is in ISO format)
        String timestamp = transaction.getTimestamp().split("T")[0];
        addCell(table, timestamp, cellFont, rowColor);

        addCell(table, transaction.getDescription(), cellFont, rowColor);
        addCell(table, transaction.getStatus(), cellFont, rowColor);
    }

    private void addCell(PdfPTable table, String content, Font font, BaseColor color) {
        PdfPCell cell = new PdfPCell(new Phrase(content, font));
        cell.setBackgroundColor(color);
        cell.setPadding(5);
        table.addCell(cell);
    }
}